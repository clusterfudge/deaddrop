"""Tests for the Turso DNS/TCP reachability monitor.

These cover the 2026-05-08 dead-IP scenario: Turso's NLB returns an IP in
DNS that is TCP-dead on :443. The monitor must:

- resolve the Turso hostname
- TCP-probe each IP
- emit per-IP reachability gauges + an `ip_count` gauge
- log a WARNING when any IP is unreachable
"""

from __future__ import annotations

import logging
import socket
from unittest.mock import MagicMock, patch

import pytest

from deadrop import db


@pytest.fixture
def libsql_env(monkeypatch):
    monkeypatch.setenv("TURSO_URL", "libsql://example-db.turso.io")
    yield


def test_turso_hostname_extracts_host(libsql_env):
    assert db._turso_hostname() == "example-db.turso.io"


def test_turso_hostname_none_when_not_libsql(monkeypatch):
    monkeypatch.setenv("TURSO_URL", "")
    assert db._turso_hostname() is None


def test_tcp_reachable_returns_false_on_timeout():
    """A fake socket that always times out should report unreachable."""
    fake_sock = MagicMock()
    fake_sock.connect.side_effect = socket.timeout("boom")

    with patch("socket.socket", return_value=fake_sock):
        assert db._tcp_reachable("10.0.0.1", port=443, timeout=0.1) is False


def test_tcp_reachable_returns_true_on_connect():
    fake_sock = MagicMock()
    fake_sock.connect.return_value = None

    with patch("socket.socket", return_value=fake_sock):
        assert db._tcp_reachable("10.0.0.2", port=443, timeout=0.1) is True


def test_dns_sweep_all_reachable_no_warning(libsql_env, caplog):
    """Happy path: every IP responds on :443. No warning emitted."""
    ips = ["3.212.35.170", "3.212.35.171"]

    def fake_gethostbyname_ex(host):
        return (host, [], ips)

    with (
        patch("socket.gethostbyname_ex", fake_gethostbyname_ex),
        patch.object(db, "_tcp_reachable", return_value=True),
        caplog.at_level(logging.WARNING),
    ):
        ip_count, unreachable = db._turso_dns_sweep()

    assert ip_count == 2
    assert unreachable == 0
    # No warning-level record about unreachable IPs
    assert not any("unreachable" in r.message.lower() for r in caplog.records)


def test_dns_sweep_flags_dead_ip(libsql_env, caplog):
    """The incident scenario: one IP in DNS is TCP-dead."""
    ips = ["3.212.35.170", "3.212.35.171"]

    # First IP dead, second IP alive — matches the 2026-05-08 profile.
    def fake_reachable(ip, port=443, timeout=3.0):
        return ip != "3.212.35.170"

    with (
        patch("socket.gethostbyname_ex", return_value=("turso", [], ips)),
        patch.object(db, "_tcp_reachable", side_effect=fake_reachable),
        caplog.at_level(logging.WARNING),
    ):
        ip_count, unreachable = db._turso_dns_sweep()

    assert ip_count == 2
    assert unreachable == 1
    # Warning mentions the dead IP explicitly so ops can grep for it.
    warning_messages = [r.message for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("3.212.35.170" in m and "unreachable" in m.lower() for m in warning_messages)


def test_dns_sweep_handles_resolution_failure(libsql_env, caplog):
    """DNS itself failing is itself a signal — log + counter, no crash."""
    with (
        patch("socket.gethostbyname_ex", side_effect=socket.gaierror("nxdomain")),
        caplog.at_level(logging.WARNING),
    ):
        ip_count, unreachable = db._turso_dns_sweep()

    assert ip_count == 0
    assert unreachable == 0
    assert any("resolution failed" in r.message for r in caplog.records)


def test_dns_sweep_noop_when_not_libsql(monkeypatch):
    """No TURSO_URL → sweep is a no-op, does not attempt DNS."""
    monkeypatch.setenv("TURSO_URL", "")

    with patch("socket.gethostbyname_ex") as fake_resolve:
        ip_count, unreachable = db._turso_dns_sweep()

    assert ip_count == 0
    assert unreachable == 0
    fake_resolve.assert_not_called()
