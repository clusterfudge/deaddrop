"""Tests for Hrana stream-not-found silent retry behavior."""

from __future__ import annotations

from unittest.mock import patch

from deadrop import db


def test_is_hrana_stream_error_detects_stream_not_found():
    err = ValueError(
        'Hrana: `api error: `status=404 Not Found, body={"error":"stream not found: abc:def"}`'
    )
    assert db._is_hrana_stream_error(err)


def test_is_hrana_stream_error_rejects_other_errors():
    err = ValueError("something unrelated")
    assert not db._is_hrana_stream_error(err)


def test_execute_with_retry_recovers_from_hrana_404(monkeypatch):
    """First call raises Hrana 404, second call succeeds."""
    # Pretend libsql backend is active so retry kicks in
    monkeypatch.setattr(db, "_is_libsql", True)

    call_count = {"n": 0}

    def flaky_op():
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise ValueError(
                'Hrana: `api error: `status=404 Not Found, body={"error":"stream not found: abc"}`'
            )
        return "ok"

    with patch.object(db, "_reset_libsql_connection"):
        result = db._execute_with_retry(flaky_op, max_retries=2)

    assert result == "ok"
    assert call_count["n"] == 2


def test_execute_with_retry_exhausts_after_max(monkeypatch):
    """Always-failing Hrana 404 eventually propagates."""
    monkeypatch.setattr(db, "_is_libsql", True)

    def always_fails():
        raise ValueError(
            'Hrana: `api error: `status=404 Not Found, body={"error":"stream not found: abc"}`'
        )

    with patch.object(db, "_reset_libsql_connection"):
        import pytest

        with pytest.raises(ValueError, match="stream not found"):
            db._execute_with_retry(always_fails, max_retries=2)


def test_execute_with_retry_doesnt_retry_non_hrana_errors(monkeypatch):
    """Non-Hrana exceptions propagate immediately, no retry."""
    monkeypatch.setattr(db, "_is_libsql", True)
    call_count = {"n": 0}

    def different_error():
        call_count["n"] += 1
        raise RuntimeError("something else entirely")

    with patch.object(db, "_reset_libsql_connection"):
        import pytest

        with pytest.raises(RuntimeError):
            db._execute_with_retry(different_error, max_retries=2)

    # Only called once — no retry
    assert call_count["n"] == 1


def test_execute_with_retry_no_retry_on_sqlite(monkeypatch):
    """With _is_libsql=False (plain sqlite3), no retry even for Hrana-looking errors."""
    monkeypatch.setattr(db, "_is_libsql", False)
    call_count = {"n": 0}

    def fails_with_hrana_message():
        call_count["n"] += 1
        raise ValueError(
            'Hrana: `api error: `status=404 Not Found, body={"error":"stream not found: abc"}`'
        )

    import pytest

    with pytest.raises(ValueError):
        db._execute_with_retry(fails_with_hrana_message, max_retries=2)

    assert call_count["n"] == 1


def test_execute_with_retry_success_on_first_try(monkeypatch):
    """Happy path: operation succeeds first time, no retry."""
    monkeypatch.setattr(db, "_is_libsql", True)
    call_count = {"n": 0}

    def ok_op():
        call_count["n"] += 1
        return "hello"

    assert db._execute_with_retry(ok_op, max_retries=2) == "hello"
    assert call_count["n"] == 1
