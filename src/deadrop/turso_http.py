"""Turso client over Hrana-over-HTTP, with a sqlite3-shaped interface.

Each statement is one ``POST /v3/pipeline`` through ``httpx``, which
releases the GIL while it waits and bounds every request with a connect and
read timeout, so a Turso request that never gets an answer fails that one
request instead of stalling the process. (The ``libsql`` Python bindings
hold the GIL across network I/O with no timeout; see issue #49 and
tursodatabase/libsql-python#113.)

Each pipeline executes the statement and closes its stream in the same
request (``baton: null`` in, ``close`` appended), so there is no
server-side session to go stale and one connection object is safe to share
across threads. That also means no multi-statement transactions; deadrop
runs Turso in autocommit mode and never opens one.

Spec: https://github.com/tursodatabase/libsql/blob/main/docs/HRANA_3_SPEC.md
"""

from __future__ import annotations

import base64
import time
from collections.abc import Iterator, Mapping, Sequence
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx

# A statement normally returns in ~50ms; these bound the pathological case.
DEFAULT_CONNECT_TIMEOUT = 5.0
DEFAULT_READ_TIMEOUT = 10.0

# Retries for failures where the request provably never reached Turso
# (connect errors, pool exhaustion), so they are safe even for writes.
CONNECT_RETRIES = 2
CONNECT_RETRY_BACKOFF = 0.2

# Kept below the idle timeout of the load balancers in front of Turso, so a
# pooled connection is never reused after an intermediary has dropped it.
KEEPALIVE_EXPIRY = 20.0


class TursoError(ValueError):
    """Error returned by Turso for a statement (syntax, constraint, auth...).

    Subclasses ValueError, the type callers of the Turso backend handle
    for database errors.
    """

    def __init__(self, message: str, code: str | None = None) -> None:
        super().__init__(message)
        self.code = code


class TursoUnavailableError(TursoError):
    """Turso did not answer: timeout, dropped connection, or a 5xx/429.

    The statement may or may not have run, so only idempotent callers
    (reads) should retry it.
    """


def http_base_url(database_url: str) -> str:
    """Map a ``libsql://host[:port]`` URL to the HTTPS URL Hrana is served on.

    ``?tls=0`` selects plain HTTP, matching libsql's convention, for a local
    ``sqld``.
    """
    parts = urlsplit(database_url)
    if parts.scheme in ("http", "https"):
        return f"{parts.scheme}://{parts.netloc}"
    if parts.scheme != "libsql":
        raise ValueError(f"Unsupported Turso URL scheme: {database_url!r}")
    tls = parse_qs(parts.query).get("tls", ["1"])[0]
    scheme = "http" if tls == "0" else "https"
    return f"{scheme}://{parts.netloc}"


def _encode_value(value: Any) -> dict[str, Any]:
    if value is None:
        return {"type": "null"}
    if isinstance(value, bool):
        return {"type": "integer", "value": str(int(value))}
    if isinstance(value, int):
        return {"type": "integer", "value": str(value)}
    if isinstance(value, float):
        return {"type": "float", "value": value}
    if isinstance(value, str):
        return {"type": "text", "value": value}
    if isinstance(value, (bytes, bytearray, memoryview)):
        return {"type": "blob", "base64": base64.b64encode(bytes(value)).decode("ascii")}
    raise TypeError(f"Unsupported parameter type for Turso: {type(value).__name__}")


def _decode_value(value: Mapping[str, Any]) -> Any:
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
        data = value["base64"]
        # Servers may omit the padding.
        return base64.b64decode(data + "=" * (-len(data) % 4))
    raise TursoError(f"Unknown Hrana value type: {kind!r}")


def _build_stmt(sql: str, params: Sequence[Any] | Mapping[str, Any]) -> dict[str, Any]:
    stmt: dict[str, Any] = {"sql": sql}
    if isinstance(params, Mapping):
        if params:
            stmt["named_args"] = [
                {"name": name, "value": _encode_value(v)} for name, v in params.items()
            ]
    elif params:
        stmt["args"] = [_encode_value(v) for v in params]
    return stmt


class TursoCursor:
    """The read side of ``sqlite3.Cursor`` for one statement's result.

    Rows are plain tuples, as the libsql bindings returned them.
    """

    arraysize = 1

    def __init__(self, result: Mapping[str, Any] | None = None) -> None:
        result = result or {}
        cols = result.get("cols") or []
        self.description: tuple[tuple[Any, ...], ...] | None = (
            tuple((col.get("name"), None, None, None, None, None, None) for col in cols)
            if cols
            else None
        )
        self._rows = [tuple(_decode_value(v) for v in row) for row in result.get("rows") or []]
        self._pos = 0
        # sqlite3 reports -1 for statements that return rows.
        self.rowcount: int = -1 if cols else int(result.get("affected_row_count") or 0)
        rowid = result.get("last_insert_rowid")
        self.lastrowid: int | None = int(rowid) if rowid is not None else None

    def fetchone(self) -> tuple | None:
        if self._pos >= len(self._rows):
            return None
        row = self._rows[self._pos]
        self._pos += 1
        return row

    def fetchmany(self, size: int | None = None) -> list[tuple]:
        size = self.arraysize if size is None else size
        rows = self._rows[self._pos : self._pos + size]
        self._pos += len(rows)
        return rows

    def fetchall(self) -> list[tuple]:
        rows = self._rows[self._pos :]
        self._pos = len(self._rows)
        return rows

    def __iter__(self) -> Iterator[tuple]:
        while (row := self.fetchone()) is not None:
            yield row

    def close(self) -> None:
        pass


class TursoConnection:
    """sqlite3-shaped connection to Turso; thread-safe and shared process-wide.

    Supports what deadrop uses: ``execute``, ``executescript``, and no-op
    ``commit``/``rollback`` (every statement autocommits).
    """

    def __init__(
        self,
        database_url: str,
        auth_token: str = "",
        *,
        connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
        read_timeout: float = DEFAULT_READ_TIMEOUT,
        max_connections: int = 32,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        headers = {"Authorization": f"Bearer {auth_token}"} if auth_token else {}
        self._client = httpx.Client(
            base_url=http_base_url(database_url),
            headers=headers,
            timeout=httpx.Timeout(read_timeout, connect=connect_timeout),
            limits=httpx.Limits(
                max_connections=max_connections,
                max_keepalive_connections=max_connections,
                keepalive_expiry=KEEPALIVE_EXPIRY,
            ),
            transport=transport,
        )
        # Accepted for sqlite3 compatibility; rows are always tuples.
        self.row_factory = None

    def execute(self, sql: str, params: Sequence[Any] | Mapping[str, Any] = ()) -> TursoCursor:
        response = self._pipeline({"type": "execute", "stmt": _build_stmt(sql, params)})
        return TursoCursor(response.get("result"))

    def executescript(self, sql: str) -> TursoCursor:
        self._pipeline({"type": "sequence", "sql": sql})
        return TursoCursor()

    def commit(self) -> None:
        pass

    def rollback(self) -> None:
        pass

    def close(self) -> None:
        self._client.close()

    def _pipeline(self, request: dict[str, Any]) -> dict[str, Any]:
        """Run one request on a fresh stream, closing it in the same round trip."""
        body = {"baton": None, "requests": [request, {"type": "close"}]}
        resp = self._post(body)

        if resp.status_code == 429 or resp.status_code >= 500:
            raise TursoUnavailableError(
                f"Turso returned HTTP {resp.status_code}: {_error_text(resp)}"
            )
        if resp.status_code >= 400:
            raise TursoError(f"Turso returned HTTP {resp.status_code}: {_error_text(resp)}")

        try:
            first = resp.json()["results"][0]
        except (ValueError, KeyError, IndexError, TypeError) as e:
            raise TursoUnavailableError(f"Malformed Hrana response: {resp.text[:200]!r}") from e
        if first.get("type") == "error":
            error = first.get("error") or {}
            raise TursoError(error.get("message", "unknown Turso error"), error.get("code"))
        return first["response"]

    def _post(self, body: dict[str, Any]) -> httpx.Response:
        for attempt in range(CONNECT_RETRIES + 1):
            try:
                return self._client.post("/v3/pipeline", json=body)
            except (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout) as e:
                # Never reached Turso, so retrying cannot apply a write twice.
                if attempt == CONNECT_RETRIES:
                    raise TursoUnavailableError(f"Could not connect to Turso: {e!r}") from e
                time.sleep(CONNECT_RETRY_BACKOFF * (attempt + 1))
            except httpx.HTTPError as e:
                # Timed out or dropped after sending: the statement may have run.
                raise TursoUnavailableError(f"Turso request failed: {e!r}") from e
        raise AssertionError("unreachable")


def _error_text(resp: httpx.Response) -> str:
    """Best-effort error message; proxies may answer with HTML or plain text."""
    try:
        data = resp.json()
    except ValueError:
        return resp.text[:200]
    if isinstance(data, dict) and "message" in data:
        return str(data["message"])
    return resp.text[:200]
