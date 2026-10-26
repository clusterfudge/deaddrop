"""Tests for the Hrana-over-HTTP Turso client (deadrop.turso_http).

The client runs against an in-process Hrana server backed by sqlite3, so the
SQL is executed for real and only the transport is faked. The stall tests
use real sockets: a server that accepts and never answers is the failure
that froze production (#49).
"""

from __future__ import annotations

import base64
import json
import socket
import sqlite3
import threading
import time

import httpx
import pytest

from deadrop import db
from deadrop.turso_http import (
    TursoConnection,
    TursoError,
    TursoUnavailableError,
    http_base_url,
)


def _decode_arg(value: dict):
    kind = value["type"]
    if kind == "null":
        return None
    if kind == "integer":
        return int(value["value"])
    if kind == "float":
        return float(value["value"])
    if kind == "text":
        return value["value"]
    if kind == "blob":
        return base64.b64decode(value["base64"])
    raise AssertionError(f"unexpected value type {kind}")


def _encode_cell(value) -> dict:
    if value is None:
        return {"type": "null"}
    if isinstance(value, int):
        return {"type": "integer", "value": str(value)}
    if isinstance(value, float):
        return {"type": "float", "value": value}
    if isinstance(value, str):
        return {"type": "text", "value": value}
    # Unpadded, as sqld sends it.
    return {"type": "blob", "base64": base64.b64encode(value).decode().rstrip("=")}


class FakeHrana:
    """A Hrana v3 HTTP server over sqlite3, as an httpx transport."""

    def __init__(self) -> None:
        self.conn = sqlite3.connect(":memory:", check_same_thread=False, isolation_level=None)
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.lock = threading.Lock()
        self.bodies: list[dict] = []
        self.headers: list[httpx.Headers] = []
        self.transport = httpx.MockTransport(self.handle)

    def handle(self, request: httpx.Request) -> httpx.Response:
        assert request.method == "POST" and request.url.path == "/v3/pipeline"
        body = json.loads(request.content)
        self.bodies.append(body)
        self.headers.append(request.headers)
        with self.lock:
            results = [self._run(req) for req in body["requests"]]
        return httpx.Response(200, json={"baton": None, "base_url": None, "results": results})

    def _run(self, req: dict) -> dict:
        try:
            if req["type"] == "close":
                return {"type": "ok", "response": {"type": "close"}}
            if req["type"] == "sequence":
                self.conn.executescript(req["sql"])
                return {"type": "ok", "response": {"type": "sequence"}}
            stmt = req["stmt"]
            if "named_args" in stmt:
                params = {
                    a["name"].lstrip(":@$"): _decode_arg(a["value"]) for a in stmt["named_args"]
                }
            else:
                params = [_decode_arg(a) for a in stmt.get("args", [])]
            cur = self.conn.execute(stmt["sql"], params)
            rows = cur.fetchall()
            result = {
                "cols": [{"name": d[0], "decltype": None} for d in cur.description or ()],
                "rows": [[_encode_cell(v) for v in row] for row in rows],
                "affected_row_count": max(cur.rowcount, 0),
                "last_insert_rowid": str(cur.lastrowid) if cur.lastrowid is not None else None,
            }
            return {"type": "ok", "response": {"type": "execute", "result": result}}
        except sqlite3.Error as e:
            return {"type": "error", "error": {"message": str(e), "code": "SQLITE_ERROR"}}


@pytest.fixture
def fake() -> FakeHrana:
    return FakeHrana()


@pytest.fixture
def conn(fake: FakeHrana):
    c = TursoConnection("libsql://db.example.turso.io", "tok", transport=fake.transport)
    yield c
    c.close()


class TestUrls:
    def test_libsql_maps_to_https(self):
        assert http_base_url("libsql://db-org.turso.io") == "https://db-org.turso.io"

    def test_tls_off_maps_to_http(self):
        assert http_base_url("libsql://127.0.0.1:8080?tls=0") == "http://127.0.0.1:8080"

    def test_http_urls_pass_through(self):
        assert http_base_url("http://127.0.0.1:8080") == "http://127.0.0.1:8080"

    def test_unknown_scheme_rejected(self):
        with pytest.raises(ValueError):
            http_base_url("postgres://nope")


class TestProtocol:
    def test_request_is_a_single_self_closing_stream(self, conn, fake):
        conn.execute("SELECT 1")
        body = fake.bodies[-1]
        assert body["baton"] is None
        assert [r["type"] for r in body["requests"]] == ["execute", "close"]
        assert fake.headers[-1]["authorization"] == "Bearer tok"

    def test_values_round_trip(self, conn):
        big = 2**62 + 1  # loses precision as a JSON number
        row = conn.execute(
            "SELECT ?, ?, ?, ?, ?, ?", (None, big, 1.5, "héllo", b"\x00\xffab", True)
        ).fetchone()
        assert row == (None, big, 1.5, "héllo", b"\x00\xffab", 1)

    def test_named_params(self, conn):
        assert conn.execute("SELECT :a + :b", {"a": 2, "b": 3}).fetchone() == (5,)

    def test_unsupported_param_type(self, conn):
        with pytest.raises(TypeError):
            conn.execute("SELECT ?", (object(),))


class TestCursor:
    def test_select_shape(self, conn):
        conn.executescript("CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT);")
        conn.execute("INSERT INTO t (name) VALUES (?)", ("a",))
        conn.execute("INSERT INTO t (name) VALUES (?)", ("b",))
        cur = conn.execute("SELECT id, name FROM t ORDER BY id")
        assert [d[0] for d in cur.description] == ["id", "name"]
        assert cur.rowcount == -1
        assert cur.fetchone() == (1, "a")
        assert cur.fetchall() == [(2, "b")]
        assert cur.fetchone() is None

    def test_dml_shape(self, conn):
        conn.executescript("CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT);")
        cur = conn.execute("INSERT INTO t (name) VALUES (?)", ("a",))
        assert cur.description is None
        assert cur.rowcount == 1
        assert cur.lastrowid == 1
        assert conn.execute("UPDATE t SET name = 'z'").rowcount == 1
        assert conn.execute("DELETE FROM t WHERE id = 99").rowcount == 0

    def test_iteration_and_fetchmany(self, conn):
        conn.executescript("CREATE TABLE t (x); INSERT INTO t VALUES (1), (2), (3);")
        cur = conn.execute("SELECT x FROM t ORDER BY x")
        assert cur.fetchmany(2) == [(1,), (2,)]
        assert list(cur) == [(3,)]

    def test_commit_and_rollback_are_noops(self, conn, fake):
        n = len(fake.bodies)
        conn.commit()
        conn.rollback()
        assert len(fake.bodies) == n


class TestErrors:
    def test_statement_error(self, conn):
        with pytest.raises(TursoError, match="no such table") as exc:
            conn.execute("SELECT * FROM missing")
        assert exc.value.code == "SQLITE_ERROR"
        assert not isinstance(exc.value, TursoUnavailableError)

    def test_statement_error_is_a_value_error(self, conn):
        with pytest.raises(ValueError):
            conn.execute("SELECT * FROM missing")

    @pytest.mark.parametrize("status", [500, 502, 503, 429])
    def test_server_errors_are_unavailable(self, status):
        transport = httpx.MockTransport(lambda r: httpx.Response(status, text="<html>bad</html>"))
        c = TursoConnection("libsql://x.turso.io", transport=transport)
        with pytest.raises(TursoUnavailableError, match=str(status)):
            c.execute("SELECT 1")

    def test_client_errors_are_not_unavailable(self):
        transport = httpx.MockTransport(
            lambda r: httpx.Response(401, json={"message": "bad token"})
        )
        c = TursoConnection("libsql://x.turso.io", transport=transport)
        with pytest.raises(TursoError, match="bad token") as exc:
            c.execute("SELECT 1")
        assert not isinstance(exc.value, TursoUnavailableError)

    def test_connect_errors_are_retried(self, fake, monkeypatch):
        monkeypatch.setattr("deadrop.turso_http.CONNECT_RETRY_BACKOFF", 0)
        attempts = {"n": 0}

        def flaky(request):
            attempts["n"] += 1
            if attempts["n"] < 3:
                raise httpx.ConnectError("refused", request=request)
            return fake.handle(request)

        c = TursoConnection("libsql://x.turso.io", transport=httpx.MockTransport(flaky))
        assert c.execute("SELECT 7").fetchone() == (7,)
        assert attempts["n"] == 3

    def test_read_timeouts_are_not_retried(self):
        """The statement may have run, so the client must not resend it."""
        attempts = {"n": 0}

        def timeout(request):
            attempts["n"] += 1
            raise httpx.ReadTimeout("slow", request=request)

        c = TursoConnection("libsql://x.turso.io", transport=httpx.MockTransport(timeout))
        with pytest.raises(TursoUnavailableError):
            c.execute("INSERT INTO t VALUES (1)")
        assert attempts["n"] == 1


@pytest.fixture
def silent_server():
    """A TCP server that accepts connections and reads but never responds."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    held: list[socket.socket] = []
    stop = threading.Event()

    def serve():
        srv.settimeout(0.1)
        while not stop.is_set():
            try:
                client, _ = srv.accept()
                held.append(client)
            except OSError:
                continue

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.getsockname()[1]}"
    stop.set()
    t.join()
    for s in held:
        s.close()
    srv.close()


class TestStalledServer:
    def test_stall_times_out(self, silent_server):
        c = TursoConnection(silent_server, read_timeout=0.5)
        start = time.monotonic()
        with pytest.raises(TursoUnavailableError):
            c.execute("SELECT 1")
        assert time.monotonic() - start < 3

    def test_stall_does_not_block_other_threads(self, silent_server):
        """The production freeze: a stalled request must not stop the interpreter."""
        c = TursoConnection(silent_server, read_timeout=2.0)
        errors: list[Exception] = []

        def blocked():
            try:
                c.execute("SELECT 1")
            except Exception as e:
                errors.append(e)

        t = threading.Thread(target=blocked)
        t.start()
        time.sleep(0.2)  # let it reach the socket wait

        start = time.monotonic()
        for _ in range(10):
            time.sleep(0.05)
        elapsed = time.monotonic() - start
        assert elapsed < 1.0, f"other threads stalled for {elapsed:.1f}s"

        t.join(timeout=5)
        assert not t.is_alive()
        assert isinstance(errors[0], TursoUnavailableError)


@pytest.fixture
def turso_backend(fake, monkeypatch):
    """Point the db layer at the fake Hrana server, as production points at Turso."""
    monkeypatch.setenv("TURSO_URL", "libsql://db.example.turso.io")
    monkeypatch.setattr(db, "_is_libsql", False)
    monkeypatch.setattr(
        db,
        "_turso_conn",
        TursoConnection("libsql://db.example.turso.io", "tok", transport=fake.transport),
    )
    db.init_db()
    return fake


class TestDbLayerOverTurso:
    def test_backend_is_selected(self, turso_backend):
        assert db.is_using_libsql()
        assert db.get_db_debug_state()["backend"] == "turso"
        db.get_connection().execute("SELECT 1")
        assert turso_backend.bodies  # schema and query went through the fake

    def test_room_flow(self, turso_backend):
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        bob = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])
        db.add_room_member(room["room_id"], bob["id"])

        db.send_room_message(room["room_id"], alice["id"], "one")
        second = db.send_room_message(room["room_id"], alice["id"], "two")

        [listed] = db.list_rooms_for_identity(ns["ns"], bob["id"])
        assert listed["has_unread"]
        assert listed["last_message_body"] == "two"
        assert db.get_room_unread_count(room["room_id"], bob["id"]) == 2

        db.update_room_read_cursor(room["room_id"], bob["id"], second["mid"])
        [listed] = db.list_rooms_for_identity(ns["ns"], bob["id"])
        assert not listed["has_unread"]

    def test_close_db_releases_the_client(self, turso_backend):
        db.close_db()
        assert db._turso_conn is None
