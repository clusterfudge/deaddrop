"""The release-phase migration entrypoint and the startup schema guard."""

import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from deadrop import db, migrate
from deadrop.api import app

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def file_db(tmp_path, monkeypatch):
    path = tmp_path / "release.db"
    db.close_db()
    monkeypatch.setenv("DEADROP_DB", str(path))
    yield path
    db.close_db()


def _version(path: Path) -> int:
    with sqlite3.connect(path) as conn:
        return conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]


def test_procfile_release_runs_the_entrypoint():
    procs = dict(
        line.split(":", 1) for line in (ROOT / "Procfile").read_text().splitlines() if line
    )
    assert procs["release"].strip() == "python -m deadrop.migrate"


def test_migrates_fresh_db_and_rerun_applies_nothing(file_db, capsys):
    assert migrate.main() == 0
    out = capsys.readouterr().out
    assert f"v0 -> v{db.SCHEMA_VERSION}" in out
    assert _version(file_db) == db.SCHEMA_VERSION

    assert migrate.main() == 0
    out = capsys.readouterr().out
    assert f"v{db.SCHEMA_VERSION} -> v{db.SCHEMA_VERSION}, applied nothing" in out


def test_failing_migration_exits_nonzero_and_stops(file_db, capsys, monkeypatch):
    def boom(conn):
        raise sqlite3.OperationalError("simulated")

    *rest, (version, desc, _) = db.MIGRATIONS
    monkeypatch.setattr(db, "MIGRATIONS", [*rest, (version, desc, boom)])

    assert migrate.main() == 1
    assert f"Migration {version} failed: simulated" in capsys.readouterr().err
    assert _version(file_db) == version - 1


def test_server_refuses_an_older_schema(monkeypatch):
    monkeypatch.delenv("DEADROP_MIGRATE_ON_START", raising=False)
    conn = db.get_connection()
    conn.execute(
        "DELETE FROM schema_version WHERE version = ?", (db.SCHEMA_VERSION,), name="test.unmigrate"
    )
    conn.commit()
    with pytest.raises(RuntimeError, match=f"needs v{db.SCHEMA_VERSION}"):
        with TestClient(app):
            pass
    assert db.get_schema_version(conn) == db.SCHEMA_VERSION - 1


def test_migrate_on_start_opt_in(monkeypatch):
    monkeypatch.setenv("DEADROP_MIGRATE_ON_START", "1")
    conn = db.get_connection()
    conn.execute(
        "DELETE FROM schema_version WHERE version = ?", (db.SCHEMA_VERSION,), name="test.unmigrate"
    )
    conn.commit()
    with TestClient(app) as client:
        assert client.get("/health").status_code == 200
    assert db.get_schema_version(db.get_connection()) == db.SCHEMA_VERSION
