"""Tests for db._execute_with_retry: which Turso failures are retried."""

from __future__ import annotations

import pytest

from deadrop import db
from deadrop.turso_http import TursoError, TursoUnavailableError


def _flaky(failures: list[Exception], result: str = "ok"):
    calls = {"n": 0}

    def op():
        calls["n"] += 1
        if failures:
            raise failures.pop(0)
        return result

    return op, calls


def test_idempotent_operation_retries_unavailable():
    op, calls = _flaky([TursoUnavailableError("read timed out")])
    assert db._execute_with_retry(op, max_retries=2, idempotent=True) == "ok"
    assert calls["n"] == 2


def test_idempotent_operation_gives_up_after_max_retries():
    op, calls = _flaky([TursoUnavailableError("down")] * 5)
    with pytest.raises(TursoUnavailableError):
        db._execute_with_retry(op, max_retries=2, idempotent=True)
    assert calls["n"] == 3


def test_non_idempotent_operation_is_not_retried():
    """A write that timed out may have applied, so it must not run twice."""
    op, calls = _flaky([TursoUnavailableError("read timed out")])
    with pytest.raises(TursoUnavailableError):
        db._execute_with_retry(op, max_retries=2)
    assert calls["n"] == 1


def test_statement_errors_are_not_retried():
    op, calls = _flaky([TursoError("UNIQUE constraint failed", "SQLITE_CONSTRAINT")])
    with pytest.raises(TursoError, match="UNIQUE"):
        db._execute_with_retry(op, max_retries=2, idempotent=True)
    assert calls["n"] == 1


def test_other_errors_are_not_retried():
    op, calls = _flaky([RuntimeError("something else entirely")])
    with pytest.raises(RuntimeError):
        db._execute_with_retry(op, max_retries=2, idempotent=True)
    assert calls["n"] == 1


def test_success_on_first_try():
    op, calls = _flaky([], result="hello")
    assert db._execute_with_retry(op, max_retries=2, idempotent=True) == "hello"
    assert calls["n"] == 1


def test_retry_is_counted_in_debug_state():
    before = db.get_db_debug_state()["turso_read_retries_total"]
    op, _ = _flaky([TursoUnavailableError("blip")])
    db._execute_with_retry(op, idempotent=True)
    assert db.get_db_debug_state()["turso_read_retries_total"] == before + 1
