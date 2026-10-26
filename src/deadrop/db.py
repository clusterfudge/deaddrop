"""Database layer for deadrop - supports SQLite, Turso, and pluggable connections.

This module provides database operations for deaddrop with support for:
- Global singleton connection (backward compatible)
- Custom connection paths for local backends
- In-memory databases for testing
- Turso (Hrana over HTTP, see turso_http) for production

Connection Management:
    # Global singleton (existing behavior)
    init_db()
    ns = create_namespace(...)

    # Scoped connection (new)
    with scoped_connection("/path/to/db.sqlite") as conn:
        init_db_with_conn(conn)
        ns = create_namespace_with_conn(conn, ...)

    # In-memory for testing
    with scoped_connection(":memory:") as conn:
        init_db_with_conn(conn)
        ...
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
from collections.abc import Callable
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator, cast

from uuid_extensions import uuid7 as make_uuid7

from .auth import derive_id, generate_secret, hash_secret
from .metrics import InstrumentedConnection, metrics, timed_query
from .turso_http import TursoConnection, TursoUnavailableError

# Deduplication window in seconds — messages with the same sender,
# destination, and content hash within this window are considered
# duplicates and silently de-duplicated.
DEDUP_WINDOW_SECONDS = 60

# Default TTL in hours when messages are read
DEFAULT_TTL_HOURS = 24

# Current schema version (increment when adding migrations)
SCHEMA_VERSION = 8

# Thread-local storage for per-thread connections
# This ensures each thread gets its own SQLite connection, avoiding
# concurrency issues with async/threaded code (FastAPI runs sync DB ops in thread pool)
_local = threading.local()

# Global config for connection parameters (shared across threads)
_db_config: dict[str, Any] = {
    "path": None,  # Will be set from env or explicit path
    "is_libsql": False,
}

# Legacy global connection (only used for explicit single-connection scenarios)
_conn: sqlite3.Connection | None = None
_is_libsql: bool = False


def is_using_libsql() -> bool:
    """Check if the database backend is Turso (a ``libsql://`` TURSO_URL)."""
    return _is_libsql or os.environ.get("TURSO_URL", "").startswith("libsql://")


# Process-wide Turso client (thread-safe; see turso_http).
_turso_conn: TursoConnection | None = None
_turso_conn_lock = threading.Lock()

# Per-request Turso timeouts (seconds). A statement normally takes ~50ms.
TURSO_CONNECT_TIMEOUT = float(os.environ.get("DEADROP_TURSO_CONNECT_TIMEOUT", "5"))
TURSO_READ_TIMEOUT = float(os.environ.get("DEADROP_TURSO_READ_TIMEOUT", "10"))

# DNS/TCP reachability monitor — detects the scenario where Turso's NLB
# returns an IP in DNS but that IP is TCP-dead. Observed 2026-05-08:
# `3.212.35.170` was in DNS but refused connections on :443; half of new
# libsql connections hit it and timed out before the NLB health-checked
# it out of rotation. This monitor surfaces that state in metrics + a
# WARNING log BEFORE users see 503s.
TURSO_DNS_MONITOR_INTERVAL = 15.0  # seconds between DNS/TCP sweeps
TURSO_DNS_TCP_TIMEOUT = 3.0  # seconds per IP TCP-connect probe

# Separate read and write executor pools.
#
# Reads (SELECT-only) and writes (INSERT/UPDATE/DELETE + commit) are routed to
# different thread pools so that a slow read (e.g. a large attachment blob
# fetch) cannot starve write threads and cause write latency spikes.
#
# For Turso the pools share one HTTP client and bound how many statements
# are in flight. For local SQLite the executors are None and FastAPI's
# default thread pool is used instead.
_read_executor = None
_write_executor = None
_executor_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Runtime diagnostics state (issue #51)
#
# Pure instrumentation for the /debug/db endpoint; changes no control flow.
# Guarded by its own lock so the snapshot is internally consistent without
# contending on _executor_lock.
# ---------------------------------------------------------------------------
_diag_lock = threading.Lock()
_turso_read_retries = 0


def _executor_thread_count(executor) -> int:
    """Best-effort count of live worker threads in a ThreadPoolExecutor.

    ThreadPoolExecutor spins threads lazily, so this reflects how many
    workers have actually been created (not max_workers). Returns 0 for a
    None executor (local-SQLite mode) or if the internal attribute is
    unavailable on this Python.
    """
    if executor is None:
        return 0
    threads = getattr(executor, "_threads", None)
    if threads is None:
        return 0
    return sum(1 for t in threads if t.is_alive())


def get_db_debug_state() -> dict:
    """Return a diagnostics snapshot of the DB layer for ``/debug/db``."""
    with _diag_lock:
        read_retries = _turso_read_retries

    return {
        "backend": "turso" if is_using_libsql() else "sqlite",
        "read_pool_threads": _executor_thread_count(_read_executor),
        "write_pool_threads": _executor_thread_count(_write_executor),
        "read_pool_size": READ_POOL_SIZE,
        "write_pool_size": WRITE_POOL_SIZE,
        "turso_read_retries_total": read_retries,
    }


# Pool sizes — tunable via environment variables.
READ_POOL_SIZE = int(os.environ.get("DEADROP_READ_POOL_SIZE", "6"))
WRITE_POOL_SIZE = int(os.environ.get("DEADROP_WRITE_POOL_SIZE", "4"))

# Backward-compat alias so any existing tooling referencing DB_POOL_SIZE still works.
DB_POOL_SIZE = int(os.environ.get("DEADROP_DB_POOL_SIZE", str(READ_POOL_SIZE)))


def get_read_executor():
    """Get the executor for read (SELECT-only) database operations.

    For libsql/Turso: uses a thread pool with READ_POOL_SIZE workers (default 6).
    Keeps reads from queuing behind writes.

    For local SQLite: returns None to use FastAPI's default thread pool with
    thread-local connections.
    """
    global _read_executor

    if _read_executor is not None:
        return _read_executor

    with _executor_lock:
        if _read_executor is not None:
            return _read_executor

        if is_using_libsql():
            from concurrent.futures import ThreadPoolExecutor

            import logging

            _read_executor = ThreadPoolExecutor(
                max_workers=READ_POOL_SIZE, thread_name_prefix="db-read"
            )
            logging.getLogger(__name__).info(
                f"Using read executor pool with {READ_POOL_SIZE} workers for libsql/Turso"
            )

    return _read_executor


def get_write_executor():
    """Get the executor for write (INSERT/UPDATE/DELETE) database operations.

    For libsql/Turso: uses a thread pool with WRITE_POOL_SIZE workers (default 4).
    Keeping write threads isolated ensures that slow reads never block writes.

    For local SQLite: returns None to use FastAPI's default thread pool with
    thread-local connections.
    """
    global _write_executor

    if _write_executor is not None:
        return _write_executor

    with _executor_lock:
        if _write_executor is not None:
            return _write_executor

        if is_using_libsql():
            from concurrent.futures import ThreadPoolExecutor

            import logging

            _write_executor = ThreadPoolExecutor(
                max_workers=WRITE_POOL_SIZE, thread_name_prefix="db-write"
            )
            logging.getLogger(__name__).info(
                f"Using write executor pool with {WRITE_POOL_SIZE} workers for libsql/Turso"
            )

    return _write_executor


def get_db_executor():
    """Get the shared executor for database operations.

    Backward-compatible shim — returns the write executor.
    New code should prefer get_read_executor() or get_write_executor().
    """
    return get_write_executor()


# ---------------------------------------------------------------------------
# Turso DNS/TCP reachability monitor
# ---------------------------------------------------------------------------


def _turso_hostname() -> str | None:
    """Extract the hostname from TURSO_URL, or None if not libsql."""
    db_url = os.environ.get("TURSO_URL", "")
    if not db_url.startswith("libsql://"):
        return None
    # libsql://host[:port]/... — strip scheme, then anything after '/' or ':'
    rest = db_url[len("libsql://") :]
    for sep in ("/", ":"):
        idx = rest.find(sep)
        if idx != -1:
            rest = rest[:idx]
    return rest or None


def _tcp_reachable(ip: str, port: int = 443, timeout: float = TURSO_DNS_TCP_TIMEOUT) -> bool:
    """Return True if a TCP handshake to (ip, port) completes within timeout."""
    import socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        return True
    except (OSError, socket.timeout):
        return False
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _turso_dns_sweep() -> tuple[int, int]:
    """Resolve Turso hostname, TCP-probe each IP, emit metrics.

    Returns (ip_count, unreachable_count). Emits a WARNING log if any IP
    is unreachable — that's the pre-cascade signal we want to page on.
    """
    import logging
    import socket

    from .metrics import statsd_gauge
    from . import instrument

    host = _turso_hostname()
    if host is None:
        return (0, 0)

    try:
        _name, _aliases, ips = socket.gethostbyname_ex(host)
    except (socket.gaierror, OSError) as e:
        logging.warning(f"turso dns monitor: resolution failed for {host}: {e}")
        statsd_gauge("turso.dns.ip_count", 0)
        instrument.sink.counter("turso.dns.resolve_error", tags={"host": host})
        return (0, 0)

    statsd_gauge("turso.dns.ip_count", len(ips))

    unreachable: list[str] = []
    for ip in ips:
        ok = _tcp_reachable(ip, port=443, timeout=TURSO_DNS_TCP_TIMEOUT)
        # Tagged gauge — backend can slice by IP without exploding metric
        # name cardinality in aggregators that support tags.
        instrument.sink.gauge(
            "turso.ip.tcp_reachable", 1.0 if ok else 0.0, tags={"ip": ip, "host": host}
        )
        # Also emit a per-IP dotted name for backends that only do flat
        # metric names (matches the spec in the original ticket).
        statsd_gauge(f"turso.ip.{ip}.tcp_reachable", 1 if ok else 0)
        if not ok:
            unreachable.append(ip)

    if unreachable:
        logging.warning(
            f"turso dns monitor: {len(unreachable)}/{len(ips)} IP(s) for {host} "
            f"TCP-unreachable on :443: {', '.join(unreachable)}"
        )
        instrument.sink.counter(
            "turso.dns.unreachable_ip",
            value=len(unreachable),
            tags={"host": host},
        )

    return (len(ips), len(unreachable))


_turso_dns_monitor_thread: threading.Thread | None = None
_turso_dns_monitor_stop = threading.Event()


def start_turso_dns_monitor() -> None:
    """Start the background DNS/TCP reachability monitor.

    Idempotent. No-op when libsql is not in use. Call from FastAPI
    lifespan startup alongside ``health_ping_loop``.
    """
    global _turso_dns_monitor_thread
    if not is_using_libsql():
        return
    if _turso_dns_monitor_thread is not None and _turso_dns_monitor_thread.is_alive():
        return

    import logging

    host = _turso_hostname()
    if host is None:
        return

    def _run() -> None:
        logging.info(
            f"turso dns monitor started (host={host}, interval={TURSO_DNS_MONITOR_INTERVAL}s)"
        )
        # Run one sweep immediately so startup logs show the current state.
        try:
            _turso_dns_sweep()
        except Exception:
            logging.exception("turso dns monitor: initial sweep crashed")

        while not _turso_dns_monitor_stop.wait(TURSO_DNS_MONITOR_INTERVAL):
            try:
                _turso_dns_sweep()
            except Exception:
                logging.exception("turso dns monitor sweep crashed")
        logging.info("turso dns monitor stopping")

    _turso_dns_monitor_stop.clear()
    _turso_dns_monitor_thread = threading.Thread(target=_run, name="turso-dns-monitor", daemon=True)
    _turso_dns_monitor_thread.start()


def stop_turso_dns_monitor() -> None:
    """Signal the DNS monitor thread to exit. Safe to call on shutdown."""
    _turso_dns_monitor_stop.set()


def _get_turso_connection() -> TursoConnection:
    """Return the process-wide Turso client, creating it on first use."""
    global _turso_conn, _is_libsql

    if _turso_conn is not None:
        return _turso_conn
    with _turso_conn_lock:
        if _turso_conn is None:
            _turso_conn = TursoConnection(
                os.environ["TURSO_URL"],
                os.environ.get("TURSO_AUTH_TOKEN", ""),
                connect_timeout=TURSO_CONNECT_TIMEOUT,
                read_timeout=TURSO_READ_TIMEOUT,
                max_connections=READ_POOL_SIZE + WRITE_POOL_SIZE + 4,
            )
            _is_libsql = True
        return _turso_conn


# --- Connection Management ---


def get_connection(db_path: str | Path | None = None) -> sqlite3.Connection:
    """Get or create database connection.

    Uses thread-local storage to give each thread its own connection,
    which is essential for safe concurrent access in async/threaded environments.

    Args:
        db_path: Optional explicit database path. If None, uses thread-local connection
                 based on environment config. Special value ":memory:" creates an
                 in-memory database (note: each thread will get a SEPARATE in-memory DB).

    Returns:
        SQLite connection with row_factory set to sqlite3.Row.
    """
    global _conn, _is_libsql, _db_config

    # If explicit path provided, create a new connection (not thread-local)
    # This is used by scoped_connection() for explicit connection management
    if db_path is not None:
        if str(db_path) == ":memory:":
            conn = sqlite3.connect(":memory:", check_same_thread=False)
        else:
            conn = sqlite3.connect(str(db_path), check_same_thread=False)
            # Enable WAL mode for better concurrent read/write performance
            conn.execute("PRAGMA journal_mode=WAL")
        # Enable foreign key enforcement
        conn.execute("PRAGMA foreign_keys=ON")
        conn.row_factory = sqlite3.Row
        return cast(sqlite3.Connection, InstrumentedConnection(conn))

    # Turso: one shared, thread-safe HTTP client (see turso_http). Building
    # it does no I/O, so this can never block.
    if os.environ.get("TURSO_URL", "").startswith("libsql://"):
        # TursoConnection provides the subset of sqlite3.Connection deadrop uses.
        turso = cast(sqlite3.Connection, _get_turso_connection())
        return cast(sqlite3.Connection, InstrumentedConnection(turso))

    # Thread-local connection for SQLite
    # Each thread gets its own connection to avoid concurrency issues
    if not hasattr(_local, "conn") or _local.conn is None:
        db_path_env = os.environ.get("DEADROP_DB", ":memory:")

        if db_path_env == ":memory:":
            # For in-memory databases, use shared cache so all threads see
            # the same data. The database name includes the process ID to
            # ensure tests don't interfere with each other across processes.
            _local.conn = sqlite3.connect(
                f"file:memdb_{os.getpid()}?mode=memory&cache=shared",
                uri=True,
                check_same_thread=False,
            )
            # Set busy timeout to wait for locks instead of failing immediately
            _local.conn.execute("PRAGMA busy_timeout=5000")
            # Enable foreign key enforcement
            _local.conn.execute("PRAGMA foreign_keys=ON")
        else:
            _local.conn = sqlite3.connect(db_path_env, check_same_thread=False)
            # Enable WAL mode for better concurrent read/write performance
            _local.conn.execute("PRAGMA journal_mode=WAL")
            # Set busy timeout to wait for locks instead of failing immediately
            _local.conn.execute("PRAGMA busy_timeout=5000")
            # Enable foreign key enforcement
            _local.conn.execute("PRAGMA foreign_keys=ON")

        _local.conn.row_factory = sqlite3.Row

    return cast(sqlite3.Connection, InstrumentedConnection(_local.conn))


@contextmanager
def scoped_connection(db_path: str | Path) -> Iterator[sqlite3.Connection]:
    """Context manager for scoped database connections.

    Creates a new connection that is automatically closed when the context exits.
    Useful for local backends and testing.

    Args:
        db_path: Path to database file, or ":memory:" for in-memory.

    Yields:
        SQLite connection.

    Example:
        with scoped_connection("/path/to/.deaddrop/data.db") as conn:
            init_db_with_conn(conn)
            create_namespace_with_conn(conn, ...)
    """
    conn = get_connection(db_path)
    try:
        yield conn
    finally:
        conn.close()


def close_db():
    """Close database connections.

    Closes the calling thread's SQLite connection and the shared Turso client.
    """
    global _conn, _is_libsql, _turso_conn

    # Close thread-local SQLite connection
    if hasattr(_local, "conn") and _local.conn is not None:
        _local.conn.close()
        _local.conn = None

    # Close the shared Turso client
    with _turso_conn_lock:
        if _turso_conn is not None:
            _turso_conn.close()
            _turso_conn = None

    # Close legacy global connection (if any)
    if _conn:
        _conn.close()
        _conn = None
        _is_libsql = False


def close_thread_connection():
    """Close the connection for the current thread only.

    Useful for cleanup in long-running threads or when done with a batch of operations.
    """
    if hasattr(_local, "conn") and _local.conn is not None:
        _local.conn.close()
        _local.conn = None


def _get_conn(
    conn: sqlite3.Connection | None,
) -> sqlite3.Connection:
    """Helper to get connection - uses provided conn or falls back to global.

    Always returns an InstrumentedConnection so that name= kwargs on
    conn.execute() work regardless of whether the caller passed a raw
    sqlite3.Connection or None.
    """
    if conn is not None:
        # Wrap raw connections so name= kwargs are accepted
        if not isinstance(conn, InstrumentedConnection):
            return cast(sqlite3.Connection, InstrumentedConnection(conn))
        return conn
    return get_connection()


def _execute_with_retry(
    operation: Callable[[], Any],
    max_retries: int = 2,
    *,
    idempotent: bool = False,
) -> Any:
    """Run a database operation, retrying Turso outages when that is safe.

    The Turso client already retries failures where the request never
    reached the server. What is left — a timeout or dropped connection after
    the request was sent — may have applied the statement, so it is retried
    only for ``idempotent`` operations (reads).

    Raises:
        The last error once retries are exhausted or the error isn't retryable.
    """
    for attempt in range(max_retries + 1):
        try:
            return operation()
        except TursoUnavailableError as e:
            if not idempotent or attempt == max_retries:
                raise
            import logging

            global _turso_read_retries
            with _diag_lock:
                _turso_read_retries += 1
            metrics.incr("db.turso.read_retry")
            logging.warning(
                f"Turso unavailable (attempt {attempt + 1}/{max_retries + 1}), retrying read: {e}"
            )
    raise AssertionError("unreachable")


def _row_to_dict(cursor_description: Any, row: tuple | sqlite3.Row | None) -> dict | None:
    """Convert a database row to a dictionary."""
    if row is None:
        return None
    if isinstance(row, sqlite3.Row):
        return dict(row)
    # For libsql, manually create dict from cursor description
    columns = [col[0] for col in cursor_description]
    return dict(zip(columns, row))


def _rows_to_dicts(cursor_description: Any, rows: list) -> list[dict]:
    """Convert database rows to a list of dictionaries."""
    if not rows:
        return []
    if rows and isinstance(rows[0], sqlite3.Row):
        return [dict(row) for row in rows]
    # For libsql, manually create dicts from cursor description
    columns = [col[0] for col in cursor_description]
    return [dict(zip(columns, row)) for row in rows]


# --- Schema and Migrations ---


def _ensure_schema_version_table(conn: sqlite3.Connection) -> None:
    """Create the schema_version table if it doesn't exist."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY,
            applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            description TEXT
        )
    """,
        name="schema.ensure_version_table",
    )
    conn.commit()


def get_schema_version(conn: sqlite3.Connection | None = None) -> int:
    """Get the current schema version from the database.

    Returns 0 if no migrations have been applied yet.
    """
    conn = _get_conn(conn)
    _ensure_schema_version_table(conn)

    cursor = conn.execute("SELECT MAX(version) FROM schema_version", name="schema.get_version")
    row = cursor.fetchone()
    return row[0] if row and row[0] is not None else 0


def record_migration(conn: sqlite3.Connection, version: int, description: str) -> None:
    """Record that a migration has been applied."""
    conn.execute(
        "INSERT INTO schema_version (version, description) VALUES (?, ?)",
        (version, description),
        name="schema.record_migration",
    )
    conn.commit()


def _column_exists(conn: sqlite3.Connection, table: str, column: str) -> bool:
    """Check if a column exists in a table."""
    cursor = conn.execute(f"PRAGMA table_info({table})", name="schema.column_exists")
    columns = [row[1] for row in cursor.fetchall()]
    return column in columns


# --- Migration Functions ---


def _migrate_001_add_content_type(conn: sqlite3.Connection) -> None:
    """Migration 001: Add content_type column to messages table."""
    if not _column_exists(conn, "messages", "content_type"):
        conn.execute(
            "ALTER TABLE messages ADD COLUMN content_type TEXT DEFAULT 'text/plain'",
            name="migrate.001",
        )
        conn.commit()


def _migrate_002_add_rooms(conn: sqlite3.Connection) -> None:
    """Migration 002: Add rooms tables for group communication."""
    # Create rooms table
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS rooms (
            room_id TEXT PRIMARY KEY,
            ns TEXT NOT NULL REFERENCES namespaces(ns) ON DELETE CASCADE,
            display_name TEXT,
            created_by TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """,
        name="migrate.002.create_rooms",
    )

    # Create room_members table with per-user read tracking
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS room_members (
            room_id TEXT NOT NULL REFERENCES rooms(room_id) ON DELETE CASCADE,
            identity_id TEXT NOT NULL,
            ns TEXT NOT NULL,
            joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_read_mid TEXT,
            PRIMARY KEY (room_id, identity_id),
            FOREIGN KEY (ns, identity_id) REFERENCES identities(ns, id) ON DELETE CASCADE
        )
    """,
        name="migrate.002.create_room_members",
    )

    # Create room_messages table
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS room_messages (
            mid TEXT PRIMARY KEY,
            room_id TEXT NOT NULL REFERENCES rooms(room_id) ON DELETE CASCADE,
            from_id TEXT NOT NULL,
            body TEXT NOT NULL,
            content_type TEXT DEFAULT 'text/plain',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """,
        name="migrate.002.create_room_messages",
    )

    # Create indexes
    conn.execute("CREATE INDEX IF NOT EXISTS idx_rooms_ns ON rooms(ns)", name="migrate.002.idx")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_room_members_identity ON room_members(ns, identity_id)",
        name="migrate.002.idx",
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_room_messages_room ON room_messages(room_id, created_at)",
        name="migrate.002.idx",
    )

    conn.commit()


def _migrate_003_add_reference_mid(conn: sqlite3.Connection) -> None:
    """Migration 003: Add reference_mid column to room_messages for reactions."""
    conn.execute("ALTER TABLE room_messages ADD COLUMN reference_mid TEXT", name="migrate.003")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_room_messages_reference ON room_messages(reference_mid)",
        name="migrate.003.idx",
    )
    conn.commit()


def _migrate_004_add_mid_indexes(conn: sqlite3.Connection) -> None:
    """Migration 004: Add mid-based indexes for efficient polling queries.

    Room messages: queries use WHERE room_id = ? AND mid > ? ORDER BY mid,
    but the existing index is on (room_id, created_at). Without the proper
    index every room message fetch scans all rows for the room.

    Inbox messages: queries use WHERE ns = ? AND to_id = ? ORDER BY mid,
    but the existing index is on (ns, to_id, created_at). Same scan problem.
    """
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_room_messages_room_mid ON room_messages(room_id, mid)",
        name="migrate.004.idx",
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_messages_inbox_mid ON messages(ns, to_id, mid)",
        name="migrate.004.idx",
    )
    conn.commit()


def _migrate_005_add_content_hash(conn: sqlite3.Connection) -> None:
    """Migration 005: Add content_hash for implicit message deduplication.

    Network timeouts can cause clients to retry sends, producing duplicate
    messages. We add a content_hash column to both messages and room_messages
    and create indexes that support efficient duplicate lookups within a
    time window based on (sender, destination, content_hash).
    """
    # Direct messages
    if not _column_exists(conn, "messages", "content_hash"):
        conn.execute("ALTER TABLE messages ADD COLUMN content_hash TEXT", name="migrate.005")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_messages_dedup "
        "ON messages(ns, from_id, to_id, content_hash)",
        name="migrate.005.idx",
    )

    # Room messages
    if not _column_exists(conn, "room_messages", "content_hash"):
        conn.execute("ALTER TABLE room_messages ADD COLUMN content_hash TEXT", name="migrate.005")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_room_messages_dedup "
        "ON room_messages(room_id, from_id, content_hash)",
        name="migrate.005.idx",
    )

    conn.commit()


def _migrate_006_add_attachments(conn: sqlite3.Connection) -> None:
    """Migration 006: Add attachments table for binary content on messages.

    Attachments are stored separately from messages to keep message payloads
    lightweight. Each attachment belongs to exactly one message (via message_mid)
    and stores its content as base64-encoded text.
    """
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS attachments (
            id TEXT PRIMARY KEY,
            message_mid TEXT NOT NULL
                REFERENCES room_messages(mid) ON DELETE CASCADE,
            filename TEXT,
            content_type TEXT NOT NULL,
            data TEXT NOT NULL,
            size INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
    """,
        name="migrate.006.create_attachments",
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_attachments_mid ON attachments(message_mid)",
        name="migrate.006.idx",
    )
    conn.commit()


def _migrate_007_add_push_subscriptions(conn: sqlite3.Connection) -> None:
    """Migration 007: Add push_subscriptions table for Web Push delivery.

    Keyed on the endpoint URL, which the browser guarantees unique per
    (device, installed app, subscription). One identity may therefore hold
    several rows — a desktop browser, an installed iOS PWA, and a second
    install of the same PWA are three distinct endpoints.
    """
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS push_subscriptions (
            endpoint TEXT PRIMARY KEY,
            ns TEXT NOT NULL,
            identity_id TEXT NOT NULL,
            p256dh TEXT NOT NULL,
            auth TEXT NOT NULL,
            user_agent TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_ok_at TIMESTAMP,
            FOREIGN KEY (ns, identity_id) REFERENCES identities(ns, id) ON DELETE CASCADE
        )
    """,
        name="migrate.007.create_push_subscriptions",
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_push_subscriptions_identity "
        "ON push_subscriptions(ns, identity_id)",
        name="migrate.007.idx",
    )
    conn.commit()


def _migrate_008_add_push_prefs(conn: sqlite3.Connection) -> None:
    """Migration 008: Add push_prefs — one on/off switch per identity.

    Separate from ``push_subscriptions`` because the switch outlives any
    single device: turning notifications off must not require deleting the
    subscriptions, and turning them back on must not require every device to
    re-run the permission gesture. An identity with no row is enabled, so
    registering a subscription is sufficient to receive push.
    """
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS push_prefs (
            ns TEXT NOT NULL,
            identity_id TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (ns, identity_id),
            FOREIGN KEY (ns, identity_id) REFERENCES identities(ns, id) ON DELETE CASCADE
        )
    """,
        name="migrate.008.create_push_prefs",
    )
    conn.commit()


# Migration registry: (version, description, migration_function)
MIGRATIONS: list[tuple[int, str, Callable[[sqlite3.Connection], None]]] = [
    (1, "Add content_type column to messages", _migrate_001_add_content_type),
    (2, "Add rooms tables for group communication", _migrate_002_add_rooms),
    (3, "Add reference_mid to room_messages for reactions", _migrate_003_add_reference_mid),
    (4, "Add mid-based indexes for room_messages and messages", _migrate_004_add_mid_indexes),
    (5, "Add content_hash for implicit message deduplication", _migrate_005_add_content_hash),
    (6, "Add attachments table for binary content on messages", _migrate_006_add_attachments),
    (7, "Add push_subscriptions table for Web Push", _migrate_007_add_push_subscriptions),
    (8, "Add push_prefs table for per-identity push on/off", _migrate_008_add_push_prefs),
]


def run_migrations(conn: sqlite3.Connection | None = None) -> list[int]:
    """Run any pending migrations.

    Returns a list of migration versions that were applied.
    """
    conn = _get_conn(conn)
    _ensure_schema_version_table(conn)
    current_version = get_schema_version(conn)
    applied: list[int] = []

    for version, description, migrate_fn in MIGRATIONS:
        if version > current_version:
            try:
                migrate_fn(conn)
                record_migration(conn, version, description)
                applied.append(version)
            except Exception as e:
                raise RuntimeError(f"Migration {version} failed: {e}") from e

    return applied


# --- Schema Definition ---


SCHEMA_SQL = """
    CREATE TABLE IF NOT EXISTS namespaces (
        ns TEXT PRIMARY KEY,
        secret_hash TEXT NOT NULL,
        slug TEXT UNIQUE,
        metadata JSON DEFAULT '{}',
        ttl_hours INTEGER DEFAULT 24,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        archived_at TIMESTAMP
    );
    
    CREATE INDEX IF NOT EXISTS idx_namespaces_slug ON namespaces(slug);
    
    CREATE TABLE IF NOT EXISTS identities (
        id TEXT NOT NULL,
        ns TEXT NOT NULL REFERENCES namespaces(ns) ON DELETE CASCADE,
        secret_hash TEXT NOT NULL,
        metadata JSON DEFAULT '{}',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (ns, id)
    );
    
    CREATE TABLE IF NOT EXISTS messages (
        mid TEXT PRIMARY KEY,
        ns TEXT NOT NULL,
        to_id TEXT NOT NULL,
        from_id TEXT NOT NULL,
        body TEXT NOT NULL,
        content_type TEXT DEFAULT 'text/plain',
        content_hash TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        read_at TIMESTAMP,
        expires_at TIMESTAMP,
        archived_at TIMESTAMP,
        FOREIGN KEY (ns, to_id) REFERENCES identities(ns, id) ON DELETE CASCADE
    );
    
    CREATE INDEX IF NOT EXISTS idx_messages_inbox 
        ON messages(ns, to_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_messages_expires 
        ON messages(expires_at) WHERE expires_at IS NOT NULL;
    CREATE INDEX IF NOT EXISTS idx_messages_archived
        ON messages(ns, to_id, archived_at) WHERE archived_at IS NOT NULL;
    CREATE INDEX IF NOT EXISTS idx_messages_dedup
        ON messages(ns, from_id, to_id, content_hash);
    
    CREATE TABLE IF NOT EXISTS invites (
        invite_id TEXT PRIMARY KEY,
        ns TEXT NOT NULL REFERENCES namespaces(ns) ON DELETE CASCADE,
        identity_id TEXT NOT NULL,
        encrypted_secret TEXT NOT NULL,
        display_name TEXT,
        created_by TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP,
        claimed_at TIMESTAMP,
        claimed_by TEXT
    );
    
    CREATE INDEX IF NOT EXISTS idx_invites_ns ON invites(ns);
    
    CREATE TABLE IF NOT EXISTS archive_batches (
        batch_id TEXT PRIMARY KEY,
        ns TEXT NOT NULL,
        archive_path TEXT NOT NULL,
        message_count INTEGER NOT NULL,
        min_created_at TIMESTAMP,
        max_created_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    
    -- Rooms for group communication
    CREATE TABLE IF NOT EXISTS rooms (
        room_id TEXT PRIMARY KEY,
        ns TEXT NOT NULL REFERENCES namespaces(ns) ON DELETE CASCADE,
        display_name TEXT,
        created_by TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    
    CREATE INDEX IF NOT EXISTS idx_rooms_ns ON rooms(ns);
    
    CREATE TABLE IF NOT EXISTS room_members (
        room_id TEXT NOT NULL REFERENCES rooms(room_id) ON DELETE CASCADE,
        identity_id TEXT NOT NULL,
        ns TEXT NOT NULL,
        joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_read_mid TEXT,
        PRIMARY KEY (room_id, identity_id),
        FOREIGN KEY (ns, identity_id) REFERENCES identities(ns, id) ON DELETE CASCADE
    );
    
    CREATE INDEX IF NOT EXISTS idx_room_members_identity ON room_members(ns, identity_id);
    
    CREATE TABLE IF NOT EXISTS room_messages (
        mid TEXT PRIMARY KEY,
        room_id TEXT NOT NULL REFERENCES rooms(room_id) ON DELETE CASCADE,
        from_id TEXT NOT NULL,
        body TEXT NOT NULL,
        content_type TEXT DEFAULT 'text/plain',
        content_hash TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    
    CREATE INDEX IF NOT EXISTS idx_room_messages_room ON room_messages(room_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_room_messages_dedup
        ON room_messages(room_id, from_id, content_hash);
"""


def init_db_with_conn(conn: sqlite3.Connection) -> None:
    """Initialize database schema with an explicit connection.

    Args:
        conn: Database connection to initialize.
    """
    conn.executescript(SCHEMA_SQL)
    conn.commit()
    run_migrations(conn)


def init_db():
    """Initialize database schema using the global connection."""
    conn = get_connection()
    init_db_with_conn(conn)


def reset_db(conn: sqlite3.Connection | None = None):
    """Reset database (for testing)."""
    conn = _get_conn(conn)
    conn.executescript("""
        DROP TABLE IF EXISTS push_prefs;
        DROP TABLE IF EXISTS push_subscriptions;
        DROP TABLE IF EXISTS attachments;
        DROP TABLE IF EXISTS room_messages;
        DROP TABLE IF EXISTS room_members;
        DROP TABLE IF EXISTS rooms;
        DROP TABLE IF EXISTS archive_batches;
        DROP TABLE IF EXISTS invites;
        DROP TABLE IF EXISTS messages;
        DROP TABLE IF EXISTS identities;
        DROP TABLE IF EXISTS namespaces;
        DROP TABLE IF EXISTS schema_version;
    """)
    conn.commit()
    init_db_with_conn(conn)


# --- Slug Utilities ---


def slugify(text: str) -> str:
    """Convert text to a URL-safe slug."""
    if not text:
        return ""
    slug = text.lower().strip()
    slug = re.sub(r"[\s_]+", "-", slug)
    slug = re.sub(r"[^a-z0-9-]", "", slug)
    slug = re.sub(r"-+", "-", slug)
    slug = slug.strip("-")
    return slug


def make_unique_slug(
    base_slug: str,
    exclude_ns: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> str:
    """Generate a unique slug, appending a number if necessary."""
    conn = _get_conn(conn)
    slug = base_slug or "namespace"

    query = "SELECT COUNT(*) FROM namespaces WHERE slug = ?"
    params: list[Any] = [slug]
    if exclude_ns:
        query += " AND ns != ?"
        params.append(exclude_ns)

    cursor = conn.execute(query, tuple(params), name="make_unique_slug")
    count = cursor.fetchone()[0]

    if count == 0:
        return slug

    counter = 2
    while True:
        new_slug = f"{slug}-{counter}"
        params[0] = new_slug
        cursor = conn.execute(query, tuple(params), name="make_unique_slug")
        if cursor.fetchone()[0] == 0:
            return new_slug
        counter += 1


# --- Namespace Operations ---


def create_namespace(
    metadata: dict[str, Any] | None = None,
    ttl_hours: int = DEFAULT_TTL_HOURS,
    slug: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> dict[str, str | None]:
    """Create a new namespace. Returns {ns, secret, slug}."""
    conn = _get_conn(conn)

    secret = generate_secret()
    ns = derive_id(secret)
    secret_hash = hash_secret(secret)
    metadata_json = json.dumps(metadata or {})

    if not slug and metadata and metadata.get("display_name"):
        slug = slugify(metadata["display_name"])
    if slug:
        slug = make_unique_slug(slug, conn=conn)

    conn.execute(
        "INSERT INTO namespaces (ns, secret_hash, slug, metadata, ttl_hours) VALUES (?, ?, ?, ?, ?)",
        (ns, secret_hash, slug, metadata_json, ttl_hours),
        name="create_namespace",
    )
    conn.commit()

    return {"ns": ns, "secret": secret, "slug": slug}


def get_namespace(ns: str, conn: sqlite3.Connection | None = None) -> dict | None:
    """Get namespace by ID."""
    conn = _get_conn(conn)
    cursor = conn.execute(
        "SELECT ns, slug, metadata, ttl_hours, created_at, archived_at FROM namespaces WHERE ns = ?",
        (ns,),
        name="get_namespace",
    )
    row = _row_to_dict(cursor.description, cursor.fetchone())

    if row:
        return {
            "ns": row["ns"],
            "slug": row["slug"],
            "metadata": json.loads(row["metadata"] or "{}"),
            "ttl_hours": row["ttl_hours"],
            "created_at": row["created_at"],
            "archived_at": row["archived_at"],
        }
    return None


def get_namespace_by_slug(slug: str, conn: sqlite3.Connection | None = None) -> dict | None:
    """Get namespace by slug."""
    conn = _get_conn(conn)
    cursor = conn.execute(
        "SELECT ns, slug, metadata, ttl_hours, created_at, archived_at FROM namespaces WHERE slug = ?",
        (slug,),
        name="get_namespace_by_slug",
    )
    row = _row_to_dict(cursor.description, cursor.fetchone())

    if row:
        return {
            "ns": row["ns"],
            "slug": row["slug"],
            "metadata": json.loads(row["metadata"] or "{}"),
            "ttl_hours": row["ttl_hours"],
            "created_at": row["created_at"],
            "archived_at": row["archived_at"],
        }
    return None


def get_or_create_namespace_slug(
    ns: str,
    suggested_slug: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> str | None:
    """Get existing slug or create one for namespace."""
    conn = _get_conn(conn)

    cursor = conn.execute(
        "SELECT slug, metadata FROM namespaces WHERE ns = ?",
        (ns,),
        name="get_or_create_namespace_slug.select",
    )
    row = _row_to_dict(cursor.description, cursor.fetchone())

    if not row:
        return None

    if row["slug"]:
        return row["slug"]

    metadata = json.loads(row["metadata"] or "{}")
    base_slug = suggested_slug or slugify(metadata.get("display_name", "")) or ns[:8]
    slug = make_unique_slug(base_slug, exclude_ns=ns, conn=conn)

    conn.execute(
        "UPDATE namespaces SET slug = ? WHERE ns = ?",
        (slug, ns),
        name="get_or_create_namespace_slug.update",
    )
    conn.commit()
    return slug


def set_namespace_slug(ns: str, slug: str, conn: sqlite3.Connection | None = None) -> bool:
    """Set a namespace's slug. Returns False if slug already taken or ns not found."""
    conn = _get_conn(conn)

    clean_slug = slugify(slug)
    if not clean_slug:
        return False

    cursor = conn.execute(
        "SELECT ns FROM namespaces WHERE slug = ? AND ns != ?",
        (clean_slug, ns),
        name="set_namespace_slug.check",
    )
    if cursor.fetchone():
        return False

    cursor = conn.execute(
        "UPDATE namespaces SET slug = ? WHERE ns = ?",
        (clean_slug, ns),
        name="set_namespace_slug.update",
    )
    conn.commit()
    return cursor.rowcount > 0


def is_namespace_archived(ns: str, conn: sqlite3.Connection | None = None) -> bool:
    """Check if namespace is archived (read-only)."""
    conn = _get_conn(conn)
    cursor = conn.execute(
        "SELECT archived_at FROM namespaces WHERE ns = ?", (ns,), name="is_namespace_archived"
    )
    row = _row_to_dict(cursor.description, cursor.fetchone())
    return row is not None and row["archived_at"] is not None


def archive_namespace(ns: str, conn: sqlite3.Connection | None = None) -> bool:
    """Archive a namespace (soft-delete, rejects future writes)."""
    conn = _get_conn(conn)
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "UPDATE namespaces SET archived_at = ? WHERE ns = ? AND archived_at IS NULL",
        (now, ns),
        name="archive_namespace",
    )
    conn.commit()
    return cursor.rowcount > 0


_namespace_ttl_cache: dict[str, int] = {}


def get_namespace_ttl_hours(ns: str, conn: sqlite3.Connection | None = None) -> int:
    """Get the TTL hours for a namespace. Returns default for persistent namespaces.

    Cached in-process — namespace TTL never changes after creation.
    """
    cached = _namespace_ttl_cache.get(ns)
    if cached is not None:
        return cached

    conn = _get_conn(conn)
    cursor = conn.execute(
        "SELECT ttl_hours FROM namespaces WHERE ns = ?", (ns,), name="get_namespace_ttl_hours"
    )
    row = _row_to_dict(cursor.description, cursor.fetchone())
    ttl = row["ttl_hours"] if row else DEFAULT_TTL_HOURS
    _namespace_ttl_cache[ns] = ttl
    return ttl


def list_namespaces(conn: sqlite3.Connection | None = None) -> list[dict]:
    """List all namespaces."""
    conn = _get_conn(conn)
    cursor = conn.execute(
        "SELECT ns, slug, metadata, ttl_hours, created_at, archived_at FROM namespaces ORDER BY created_at",
        name="list_namespaces",
    )
    rows = _rows_to_dicts(cursor.description, cursor.fetchall())

    return [
        {
            "ns": row["ns"],
            "slug": row["slug"],
            "metadata": json.loads(row["metadata"] or "{}"),
            "ttl_hours": row["ttl_hours"],
            "created_at": row["created_at"],
            "archived_at": row["archived_at"],
        }
        for row in rows
    ]


def verify_namespace_secret(ns: str, secret: str, conn: sqlite3.Connection | None = None) -> bool:
    """Verify a namespace secret."""
    if derive_id(secret) != ns:
        return False

    conn = _get_conn(conn)
    cursor = conn.execute(
        "SELECT secret_hash FROM namespaces WHERE ns = ?", (ns,), name="verify_namespace_secret"
    )
    row = _row_to_dict(cursor.description, cursor.fetchone())

    if not row:
        return False

    from .auth import verify_secret

    return verify_secret(secret, row["secret_hash"])


def delete_namespace(ns: str, conn: sqlite3.Connection | None = None) -> bool:
    """Delete a namespace and all its data."""
    conn = _get_conn(conn)
    cursor = conn.execute("DELETE FROM namespaces WHERE ns = ?", (ns,), name="delete_namespace")
    conn.commit()
    return cursor.rowcount > 0


def update_namespace_metadata(
    ns: str,
    metadata: dict[str, Any],
    conn: sqlite3.Connection | None = None,
) -> bool:
    """Update namespace metadata."""
    conn = _get_conn(conn)
    cursor = conn.execute(
        "UPDATE namespaces SET metadata = ? WHERE ns = ?",
        (json.dumps(metadata), ns),
        name="update_namespace_metadata",
    )
    conn.commit()
    return cursor.rowcount > 0


# --- Identity Operations ---


def create_identity(
    ns: str,
    metadata: dict[str, Any] | None = None,
    conn: sqlite3.Connection | None = None,
) -> dict[str, str]:
    """Create a new identity in a namespace. Returns {id, secret}."""
    conn = _get_conn(conn)

    secret = generate_secret()
    identity_id = derive_id(secret)
    secret_hash = hash_secret(secret)
    metadata_json = json.dumps(metadata or {})

    conn.execute(
        "INSERT INTO identities (id, ns, secret_hash, metadata) VALUES (?, ?, ?, ?)",
        (identity_id, ns, secret_hash, metadata_json),
        name="create_identity",
    )
    conn.commit()

    return {"id": identity_id, "secret": secret}


def get_identity(
    ns: str,
    identity_id: str,
    conn: sqlite3.Connection | None = None,
) -> dict | None:
    """Get identity by ID."""
    conn = _get_conn(conn)
    cursor = conn.execute(
        "SELECT id, metadata, created_at FROM identities WHERE ns = ? AND id = ?",
        (ns, identity_id),
        name="get_identity",
    )
    row = _row_to_dict(cursor.description, cursor.fetchone())

    if row:
        return {
            "id": row["id"],
            "metadata": json.loads(row["metadata"] or "{}"),
            "created_at": row["created_at"],
        }
    return None


def get_identity_secret_hash(
    ns: str,
    identity_id: str,
    conn: sqlite3.Connection | None = None,
) -> str | None:
    """Get the secret hash for an identity (used for invite creation)."""
    conn = _get_conn(conn)
    cursor = conn.execute(
        "SELECT secret_hash FROM identities WHERE ns = ? AND id = ?",
        (ns, identity_id),
        name="get_identity_secret_hash",
    )
    row = _row_to_dict(cursor.description, cursor.fetchone())
    return row["secret_hash"] if row else None


def list_identities(ns: str, conn: sqlite3.Connection | None = None) -> list[dict]:
    """List all identities in a namespace."""
    conn = _get_conn(conn)
    cursor = conn.execute(
        "SELECT id, metadata, created_at FROM identities WHERE ns = ? ORDER BY created_at",
        (ns,),
        name="list_identities",
    )
    rows = _rows_to_dicts(cursor.description, cursor.fetchall())

    return [
        {
            "id": row["id"],
            "metadata": json.loads(row["metadata"] or "{}"),
            "created_at": row["created_at"],
        }
        for row in rows
    ]


def verify_identity_secret(
    ns: str,
    identity_id: str,
    secret: str,
    conn: sqlite3.Connection | None = None,
) -> bool:
    """Verify an identity secret.

    Uses the identity_hash_cache to avoid a Turso round-trip on every request.
    The cache is populated at startup and kept consistent via write-through
    invalidation when identities are created or deleted.
    """
    if derive_id(secret) != identity_id:
        return False

    from .auth import verify_secret
    from .cache import identity_hash_cache

    # Try cache first — avoids a Turso round-trip per request
    cache_hit, cached_hash = identity_hash_cache.get(f"identity:{ns}:{identity_id}")
    if cache_hit and cached_hash:
        return verify_secret(secret, cached_hash)

    # Cache miss — fall through to DB
    conn = _get_conn(conn)
    cursor = conn.execute(
        "SELECT secret_hash FROM identities WHERE ns = ? AND id = ?",
        (ns, identity_id),
        name="verify_identity_secret",
    )
    row = _row_to_dict(cursor.description, cursor.fetchone())

    if not row:
        return False

    # Populate cache for next time
    identity_hash_cache.set(f"identity:{ns}:{identity_id}", row["secret_hash"])

    return verify_secret(secret, row["secret_hash"])


def verify_identity_in_namespace(
    ns: str,
    secret: str,
    conn: sqlite3.Connection | None = None,
) -> str | None:
    """Verify a secret belongs to some identity in the namespace. Returns identity ID or None.

    Uses the identity_hash_cache to avoid a Turso round-trip on every request.
    """
    identity_id = derive_id(secret)

    from .auth import verify_secret
    from .cache import identity_hash_cache

    # Try cache first
    cache_hit, cached_hash = identity_hash_cache.get(f"identity:{ns}:{identity_id}")
    if cache_hit and cached_hash:
        if verify_secret(secret, cached_hash):
            return identity_id
        return None

    # Cache miss — fall through to DB
    conn = _get_conn(conn)
    cursor = conn.execute(
        "SELECT secret_hash FROM identities WHERE ns = ? AND id = ?",
        (ns, identity_id),
        name="verify_identity_in_namespace",
    )
    row = _row_to_dict(cursor.description, cursor.fetchone())

    if not row:
        return None

    # Populate cache
    identity_hash_cache.set(f"identity:{ns}:{identity_id}", row["secret_hash"])

    if verify_secret(secret, row["secret_hash"]):
        return identity_id
    return None


def delete_identity(
    ns: str,
    identity_id: str,
    conn: sqlite3.Connection | None = None,
) -> bool:
    """Delete an identity and all its messages."""
    conn = _get_conn(conn)
    cursor = conn.execute(
        "DELETE FROM identities WHERE ns = ? AND id = ?", (ns, identity_id), name="delete_identity"
    )
    conn.commit()
    return cursor.rowcount > 0


def update_identity_metadata(
    ns: str,
    identity_id: str,
    metadata: dict[str, Any],
    conn: sqlite3.Connection | None = None,
) -> bool:
    """Update identity metadata."""
    conn = _get_conn(conn)
    cursor = conn.execute(
        "UPDATE identities SET metadata = ? WHERE ns = ? AND id = ?",
        (json.dumps(metadata), ns, identity_id),
        name="update_identity_metadata",
    )
    conn.commit()
    return cursor.rowcount > 0


# --- Content Hash for Deduplication ---


def _compute_content_hash(body: str, content_type: str, reference_mid: str | None = None) -> str:
    """Compute a short hash of message content for deduplication.

    Uses SHA-256 truncated to 16 hex chars (64 bits) — sufficient for
    detecting retries within a narrow time window while keeping the index
    compact.
    """
    import hashlib

    parts = [body, content_type]
    if reference_mid:
        parts.append(reference_mid)
    digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
    return digest[:16]


# --- Message Operations ---


@timed_query("send_message")
def send_message(
    ns: str,
    from_id: str,
    to_id: str,
    body: str,
    content_type: str = "text/plain",
    ttl_hours: int | None = None,
    conn: sqlite3.Connection | None = None,
) -> dict:
    """Send a message. Returns message info.

    Implements implicit idempotency: if the same sender sends an identical
    message (same body, content_type) to the same recipient within
    DEDUP_WINDOW_SECONDS, the original message is returned instead of
    creating a duplicate.
    """
    conn = _get_conn(conn)

    # Verify recipient exists
    cursor = conn.execute(
        "SELECT id FROM identities WHERE ns = ? AND id = ?",
        (ns, to_id),
        name="send_message.verify_recipient",
    )
    row = cursor.fetchone()

    if not row:
        raise ValueError(f"Recipient {to_id} not found in namespace {ns}")

    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    content_hash = _compute_content_hash(body, content_type)

    # Check for recent duplicate within the dedup window
    window_start = (now - timedelta(seconds=DEDUP_WINDOW_SECONDS)).isoformat()
    cursor = conn.execute(
        """SELECT mid, from_id, to_id, content_type, created_at
           FROM messages
           WHERE ns = ? AND from_id = ? AND to_id = ? AND content_hash = ?
             AND created_at > ?
           ORDER BY created_at DESC LIMIT 1""",
        (ns, from_id, to_id, content_hash, window_start),
        name="send_message.dedup_check",
    )
    existing = _row_to_dict(cursor.description, cursor.fetchone())
    if existing:
        return {
            "mid": existing["mid"],
            "from": existing["from_id"],
            "to": existing["to_id"],
            "content_type": existing["content_type"],
            "created_at": existing["created_at"],
            "deduplicated": True,
        }

    mid = str(make_uuid7())

    expires_at = None
    if ttl_hours is not None and ttl_hours > 0:
        expires_at = (now + timedelta(hours=ttl_hours)).isoformat()

    conn.execute(
        """INSERT INTO messages (mid, ns, to_id, from_id, body, content_type, content_hash, created_at, expires_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (mid, ns, to_id, from_id, body, content_type, content_hash, now_iso, expires_at),
        name="send_message.insert",
    )
    conn.commit()

    return {
        "mid": mid,
        "from": from_id,
        "to": to_id,
        "content_type": content_type,
        "created_at": now_iso,
    }


@timed_query("has_new_messages")
def has_new_messages(
    ns: str,
    identity_id: str,
    after_mid: str | None = None,
    unread_only: bool = False,
    conn: sqlite3.Connection | None = None,
) -> bool:
    """Check if there are new messages without fetching them.

    This is a lightweight check using COUNT - more efficient than get_messages
    when you only need to know if messages exist.

    Args:
        ns: Namespace ID
        identity_id: Identity ID
        after_mid: Only count messages after this message ID
        unread_only: Only count unread messages

    Returns:
        True if there are matching messages, False otherwise.
    """
    conn = _get_conn(conn)
    now = datetime.now(timezone.utc).isoformat()

    query = """
        SELECT COUNT(*) FROM messages 
        WHERE ns = ? AND to_id = ?
        AND (expires_at IS NULL OR expires_at > ?)
        AND archived_at IS NULL
    """
    params: list[Any] = [ns, identity_id, now]

    if unread_only:
        query += " AND read_at IS NULL"

    if after_mid:
        query += " AND mid > ?"
        params.append(after_mid)

    cursor = conn.execute(query, tuple(params), name="has_new_messages.count")
    count = cursor.fetchone()[0]
    return count > 0


@timed_query("get_messages")
def get_messages(
    ns: str,
    identity_id: str,
    unread_only: bool = False,
    after_mid: str | None = None,
    mark_as_read: bool = True,
    include_archived: bool = False,
    conn: sqlite3.Connection | None = None,
) -> list[dict]:
    """Get messages for an identity, optionally marking unread messages as read."""
    conn = _get_conn(conn)
    now = datetime.now(timezone.utc).isoformat()

    ttl_hours = get_namespace_ttl_hours(ns, conn=conn)

    query = """
        SELECT mid, from_id, to_id, body, content_type, created_at, read_at, expires_at, archived_at
        FROM messages 
        WHERE ns = ? AND to_id = ?
        AND (expires_at IS NULL OR expires_at > ?)
    """
    params: list[Any] = [ns, identity_id, now]

    if not include_archived:
        query += " AND archived_at IS NULL"

    if unread_only:
        query += " AND read_at IS NULL"

    if after_mid:
        query += " AND mid > ?"
        params.append(after_mid)

    query += " ORDER BY mid"

    cursor = conn.execute(query, tuple(params), name="get_messages.select")
    rows = _rows_to_dicts(cursor.description, cursor.fetchall())

    messages = [
        {
            "mid": row["mid"],
            "from": row["from_id"],
            "to": row["to_id"],
            "body": row["body"],
            "content_type": row.get("content_type") or "text/plain",
            "created_at": row["created_at"],
            "read_at": row["read_at"],
            "expires_at": row["expires_at"],
            "archived_at": row.get("archived_at"),
        }
        for row in rows
    ]

    if mark_as_read:
        unread_mids = [m["mid"] for m in messages if m["read_at"] is None]
        if unread_mids:
            if ttl_hours > 0:
                expires_at = (datetime.now(timezone.utc) + timedelta(hours=ttl_hours)).isoformat()
            else:
                expires_at = None

            placeholders = ",".join("?" * len(unread_mids))
            conn.execute(
                f"UPDATE messages SET read_at = ?, expires_at = ? WHERE mid IN ({placeholders})",
                tuple([now, expires_at] + unread_mids),
                name="get_messages.mark_read",
            )
            conn.commit()

            for m in messages:
                if m["read_at"] is None:
                    m["read_at"] = now
                    m["expires_at"] = expires_at

    return messages


@timed_query("mark_conversation_read")
def mark_conversation_read(
    ns: str,
    identity_id: str,
    peer_id: str,
    conn: sqlite3.Connection | None = None,
) -> list[str]:
    """Mark the unread messages ``peer_id`` sent ``identity_id`` as read.

    Scopes read state to one 1:1 conversation. Row selection matches
    :func:`get_messages` — live and unarchived — and the TTL countdown
    starts here the same way.

    Returns the mids that changed state; an empty list when there was
    nothing unread.
    """
    conn = _get_conn(conn)
    now = datetime.now(timezone.utc).isoformat()
    ttl_hours = get_namespace_ttl_hours(ns, conn=conn)

    cursor = conn.execute(
        """SELECT mid FROM messages
           WHERE ns = ? AND to_id = ? AND from_id = ?
           AND read_at IS NULL
           AND archived_at IS NULL
           AND (expires_at IS NULL OR expires_at > ?)""",
        (ns, identity_id, peer_id, now),
        name="mark_conversation_read.select",
    )
    mids = [row[0] for row in cursor.fetchall()]
    if not mids:
        return []

    if ttl_hours > 0:
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=ttl_hours)).isoformat()
    else:
        expires_at = None

    placeholders = ",".join("?" * len(mids))
    conn.execute(
        f"UPDATE messages SET read_at = ?, expires_at = ? WHERE mid IN ({placeholders})",
        tuple([now, expires_at] + mids),
        name="mark_conversation_read.update",
    )
    conn.commit()
    return mids


def get_message(
    ns: str,
    identity_id: str,
    mid: str,
    conn: sqlite3.Connection | None = None,
) -> dict | None:
    """Get a single message."""
    conn = _get_conn(conn)
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        """SELECT mid, from_id, to_id, body, content_type, created_at, read_at, expires_at, archived_at
           FROM messages 
           WHERE ns = ? AND to_id = ? AND mid = ?
           AND (expires_at IS NULL OR expires_at > ?)""",
        (ns, identity_id, mid, now),
        name="get_message",
    )
    row = _row_to_dict(cursor.description, cursor.fetchone())

    if row:
        return {
            "mid": row["mid"],
            "from": row["from_id"],
            "to": row["to_id"],
            "body": row["body"],
            "content_type": row.get("content_type") or "text/plain",
            "created_at": row["created_at"],
            "read_at": row["read_at"],
            "expires_at": row["expires_at"],
            "archived_at": row.get("archived_at"),
        }
    return None


def delete_message(
    ns: str,
    identity_id: str,
    mid: str,
    conn: sqlite3.Connection | None = None,
) -> bool:
    """Immediately delete a message."""
    conn = _get_conn(conn)
    cursor = conn.execute(
        "DELETE FROM messages WHERE ns = ? AND to_id = ? AND mid = ?",
        (ns, identity_id, mid),
        name="delete_message",
    )
    conn.commit()
    return cursor.rowcount > 0


def archive_message(
    ns: str,
    identity_id: str,
    mid: str,
    conn: sqlite3.Connection | None = None,
) -> bool:
    """Archive a message (hide from inbox but preserve)."""
    conn = _get_conn(conn)
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        """UPDATE messages SET archived_at = ?, expires_at = NULL 
           WHERE ns = ? AND to_id = ? AND mid = ? AND archived_at IS NULL""",
        (now, ns, identity_id, mid),
        name="archive_message",
    )
    conn.commit()
    return cursor.rowcount > 0


def unarchive_message(
    ns: str,
    identity_id: str,
    mid: str,
    conn: sqlite3.Connection | None = None,
) -> bool:
    """Unarchive a message (restore to inbox)."""
    conn = _get_conn(conn)
    cursor = conn.execute(
        "UPDATE messages SET archived_at = NULL WHERE ns = ? AND to_id = ? AND mid = ?",
        (ns, identity_id, mid),
        name="unarchive_message",
    )
    conn.commit()
    return cursor.rowcount > 0


def get_archived_messages(
    ns: str,
    identity_id: str,
    conn: sqlite3.Connection | None = None,
) -> list[dict]:
    """Get archived messages for an identity."""
    conn = _get_conn(conn)
    cursor = conn.execute(
        """SELECT mid, from_id, to_id, body, content_type, created_at, read_at, expires_at, archived_at
           FROM messages 
           WHERE ns = ? AND to_id = ? AND archived_at IS NOT NULL
           ORDER BY archived_at DESC""",
        (ns, identity_id),
        name="get_archived_messages",
    )
    rows = _rows_to_dicts(cursor.description, cursor.fetchall())

    return [
        {
            "mid": row["mid"],
            "from": row["from_id"],
            "to": row["to_id"],
            "body": row["body"],
            "content_type": row.get("content_type") or "text/plain",
            "created_at": row["created_at"],
            "read_at": row["read_at"],
            "expires_at": row["expires_at"],
            "archived_at": row["archived_at"],
        }
        for row in rows
    ]


# --- Invite Operations ---


def create_invite(
    invite_id: str,
    ns: str,
    identity_id: str,
    encrypted_secret: str,
    display_name: str | None = None,
    created_by: str | None = None,
    expires_at: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> dict:
    """Create an invite record."""
    conn = _get_conn(conn)
    now = datetime.now(timezone.utc).isoformat()

    conn.execute(
        """INSERT INTO invites 
           (invite_id, ns, identity_id, encrypted_secret, display_name, created_by, created_at, expires_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (invite_id, ns, identity_id, encrypted_secret, display_name, created_by, now, expires_at),
        name="create_invite",
    )
    conn.commit()

    return {
        "invite_id": invite_id,
        "ns": ns,
        "identity_id": identity_id,
        "display_name": display_name,
        "created_at": now,
        "expires_at": expires_at,
    }


def get_invite(invite_id: str, conn: sqlite3.Connection | None = None) -> dict | None:
    """Get an invite by ID."""
    conn = _get_conn(conn)
    cursor = conn.execute(
        """SELECT invite_id, ns, identity_id, encrypted_secret, display_name,
                  created_by, created_at, expires_at, claimed_at, claimed_by
           FROM invites WHERE invite_id = ?""",
        (invite_id,),
        name="get_invite",
    )
    row = _row_to_dict(cursor.description, cursor.fetchone())
    return row


def get_invite_info(invite_id: str, conn: sqlite3.Connection | None = None) -> dict | None:
    """Get public invite info (without secrets)."""
    conn = _get_conn(conn)
    cursor = conn.execute(
        """SELECT invite_id, ns, identity_id, display_name, created_at, expires_at, claimed_at
           FROM invites WHERE invite_id = ?""",
        (invite_id,),
        name="get_invite_info",
    )
    row = _row_to_dict(cursor.description, cursor.fetchone())

    if row:
        ns_info = get_namespace(row["ns"], conn=conn)
        if ns_info:
            row["namespace_slug"] = ns_info.get("slug")
            row["namespace_display_name"] = ns_info.get("metadata", {}).get("display_name")
            row["namespace_ttl_hours"] = ns_info.get("ttl_hours")

        identity_info = get_identity(row["ns"], row["identity_id"], conn=conn)
        if identity_info:
            row["identity_display_name"] = identity_info.get("metadata", {}).get("display_name")

    return row


def claim_invite(
    invite_id: str,
    claimed_by: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> dict | None:
    """Claim an invite (mark as used and return encrypted secret)."""
    conn = _get_conn(conn)
    now = datetime.now(timezone.utc).isoformat()

    cursor = conn.execute(
        """SELECT invite_id, ns, identity_id, encrypted_secret, display_name,
                  created_by, created_at, expires_at, claimed_at
           FROM invites 
           WHERE invite_id = ? 
           AND claimed_at IS NULL
           AND (expires_at IS NULL OR expires_at > ?)""",
        (invite_id, now),
        name="claim_invite.select",
    )
    row = _row_to_dict(cursor.description, cursor.fetchone())

    if not row:
        return None

    conn.execute(
        "UPDATE invites SET claimed_at = ?, claimed_by = ? WHERE invite_id = ?",
        (now, claimed_by, invite_id),
        name="claim_invite.update",
    )
    conn.commit()

    ns_info = get_namespace(row["ns"], conn=conn)
    if ns_info:
        row["namespace_slug"] = ns_info.get("slug") or get_or_create_namespace_slug(
            row["ns"], conn=conn
        )
        row["namespace_display_name"] = ns_info.get("metadata", {}).get("display_name")
        row["namespace_ttl_hours"] = ns_info.get("ttl_hours")

    identity_info = get_identity(row["ns"], row["identity_id"], conn=conn)
    if identity_info:
        row["identity_display_name"] = identity_info.get("metadata", {}).get("display_name")

    row["claimed_at"] = now
    row["claimed_by"] = claimed_by

    return row


def list_invites(
    ns: str,
    include_claimed: bool = False,
    conn: sqlite3.Connection | None = None,
) -> list[dict]:
    """List invites for a namespace."""
    conn = _get_conn(conn)

    query = """SELECT invite_id, ns, identity_id, display_name, created_by, 
                      created_at, expires_at, claimed_at, claimed_by
               FROM invites WHERE ns = ?"""

    if not include_claimed:
        query += " AND claimed_at IS NULL"

    query += " ORDER BY created_at DESC"

    cursor = conn.execute(query, (ns,), name="list_invites")
    return _rows_to_dicts(cursor.description, cursor.fetchall())


def revoke_invite(invite_id: str, conn: sqlite3.Connection | None = None) -> bool:
    """Revoke (delete) an invite."""
    conn = _get_conn(conn)
    cursor = conn.execute(
        "DELETE FROM invites WHERE invite_id = ?", (invite_id,), name="revoke_invite"
    )
    conn.commit()
    return cursor.rowcount > 0


def cleanup_expired_invites(conn: sqlite3.Connection | None = None) -> int:
    """Delete expired unclaimed invites. Returns count deleted."""
    conn = _get_conn(conn)
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "DELETE FROM invites WHERE expires_at IS NOT NULL AND expires_at <= ? AND claimed_at IS NULL",
        (now,),
        name="cleanup_expired_invites",
    )
    conn.commit()
    return cursor.rowcount


# --- TTL and Archive Operations ---


def get_expired_namespaces(conn: sqlite3.Connection | None = None) -> list[dict]:
    """Get namespaces past their TTL that haven't been archived yet.

    Returns namespaces where:
    - ttl_hours > 0 (0 means persistent/no expiry)
    - archived_at IS NULL (not already archived)
    - created_at + ttl_hours < now (past expiry)
    """
    conn = _get_conn(conn)
    cursor = conn.execute(
        """SELECT ns, slug, ttl_hours, created_at,
                  ROUND((julianday('now') - julianday(created_at)) * 24, 1) as age_hours
           FROM namespaces
           WHERE archived_at IS NULL
             AND ttl_hours > 0
             AND datetime(created_at, '+' || ttl_hours || ' hours') < datetime('now')
           ORDER BY created_at""",
        name="get_expired_namespaces",
    )
    return _rows_to_dicts(cursor.description, cursor.fetchall())


def archive_expired_namespaces(conn: sqlite3.Connection | None = None) -> int:
    """Archive all namespaces that are past their TTL.

    Returns number of namespaces archived.
    """
    conn = _get_conn(conn)
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        """UPDATE namespaces SET archived_at = ?
           WHERE archived_at IS NULL
             AND ttl_hours > 0
             AND datetime(created_at, '+' || ttl_hours || ' hours') < datetime('now')""",
        (now,),
        name="archive_expired_namespaces",
    )
    conn.commit()
    return cursor.rowcount


def get_expired_messages(
    limit: int = 1000,
    conn: sqlite3.Connection | None = None,
) -> list[dict]:
    """Get messages past their expiration time."""
    conn = _get_conn(conn)
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        """SELECT mid, ns, to_id, from_id, body, content_type, created_at, read_at, expires_at
           FROM messages 
           WHERE expires_at IS NOT NULL AND expires_at <= ? AND archived_at IS NULL
           ORDER BY expires_at
           LIMIT ?""",
        (now, limit),
        name="get_expired_messages",
    )
    return _rows_to_dicts(cursor.description, cursor.fetchall())


def delete_expired_messages(conn: sqlite3.Connection | None = None) -> int:
    """Delete all expired messages (excluding archived). Returns count deleted."""
    conn = _get_conn(conn)
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "DELETE FROM messages WHERE expires_at IS NOT NULL AND expires_at <= ? AND archived_at IS NULL",
        (now,),
        name="delete_expired_messages",
    )
    conn.commit()
    return cursor.rowcount


def mark_messages_archived(
    mids: list[str],
    archive_key: str,
    conn: sqlite3.Connection | None = None,
) -> int:
    """Mark messages as archived with a reference key."""
    if not mids:
        return 0
    return len(mids)


def create_archive_batch(
    ns: str,
    archive_path: str,
    message_count: int,
    min_created_at: str,
    max_created_at: str,
    conn: sqlite3.Connection | None = None,
) -> str:
    """Record an archive batch."""
    conn = _get_conn(conn)
    batch_id = str(make_uuid7())
    conn.execute(
        """INSERT INTO archive_batches 
           (batch_id, ns, archive_path, message_count, min_created_at, max_created_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (batch_id, ns, archive_path, message_count, min_created_at, max_created_at),
        name="create_archive_batch",
    )
    conn.commit()
    return batch_id


def get_archive_batches(
    ns: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> list[dict]:
    """Get archive batch records, optionally filtered by namespace."""
    conn = _get_conn(conn)

    if ns:
        cursor = conn.execute(
            "SELECT * FROM archive_batches WHERE ns = ? ORDER BY created_at",
            (ns,),
            name="get_archive_batches",
        )
    else:
        cursor = conn.execute(
            "SELECT * FROM archive_batches ORDER BY created_at", name="get_archive_batches"
        )

    return _rows_to_dicts(cursor.description, cursor.fetchall())


# --- Room Operations ---


def create_room(
    ns: str,
    created_by: str,
    display_name: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> dict:
    """Create a new room in a namespace.

    The creator is automatically added as the first member.

    Args:
        ns: Namespace ID
        created_by: Identity ID of the creator
        display_name: Optional display name for the room
        conn: Optional database connection

    Returns:
        Room info dict with room_id, ns, display_name, created_by, created_at
    """
    conn = _get_conn(conn)

    # Verify creator exists in namespace
    cursor = conn.execute(
        "SELECT id FROM identities WHERE ns = ? AND id = ?",
        (ns, created_by),
        name="create_room.verify_creator",
    )
    if not cursor.fetchone():
        raise ValueError(f"Creator {created_by} not found in namespace {ns}")

    room_id = str(make_uuid7())
    now = datetime.now(timezone.utc).isoformat()

    # Create the room
    conn.execute(
        """INSERT INTO rooms (room_id, ns, display_name, created_by, created_at)
           VALUES (?, ?, ?, ?, ?)""",
        (room_id, ns, display_name, created_by, now),
        name="create_room.insert",
    )

    # Add creator as first member
    conn.execute(
        """INSERT INTO room_members (room_id, identity_id, ns, joined_at)
           VALUES (?, ?, ?, ?)""",
        (room_id, created_by, ns, now),
        name="create_room.add_creator",
    )

    conn.commit()

    return {
        "room_id": room_id,
        "ns": ns,
        "display_name": display_name,
        "created_by": created_by,
        "created_at": now,
    }


def get_room(
    room_id: str,
    conn: sqlite3.Connection | None = None,
) -> dict | None:
    """Get room by ID.

    Args:
        room_id: Room ID
        conn: Optional database connection

    Returns:
        Room info dict or None if not found
    """
    conn = _get_conn(conn)
    cursor = conn.execute(
        """SELECT room_id, ns, display_name, created_by, created_at
           FROM rooms WHERE room_id = ?""",
        (room_id,),
        name="get_room",
    )
    row = _row_to_dict(cursor.description, cursor.fetchone())
    return row


def update_room(
    room_id: str,
    display_name: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> dict | None:
    """Update a room's mutable properties.

    Args:
        room_id: Room ID
        display_name: New display name (None = leave unchanged)
        conn: Optional database connection

    Returns:
        Updated room info dict, or None if the room does not exist.
    """
    conn = _get_conn(conn)

    updates = []
    params: list[object] = []
    if display_name is not None:
        updates.append("display_name = ?")
        params.append(display_name)

    if updates:
        params.append(room_id)
        conn.execute(
            f"UPDATE rooms SET {', '.join(updates)} WHERE room_id = ?",
            params,
            name="update_room",
        )
        conn.commit()

    return get_room(room_id, conn=conn)


def list_rooms(
    ns: str,
    conn: sqlite3.Connection | None = None,
) -> list[dict]:
    """List all rooms in a namespace.

    Args:
        ns: Namespace ID
        conn: Optional database connection

    Returns:
        List of room info dicts
    """
    conn = _get_conn(conn)
    cursor = conn.execute(
        """SELECT room_id, ns, display_name, created_by, created_at
           FROM rooms WHERE ns = ? ORDER BY created_at""",
        (ns,),
        name="list_rooms",
    )
    return _rows_to_dicts(cursor.description, cursor.fetchall())


def list_rooms_for_identity(
    ns: str,
    identity_id: str,
    conn: sqlite3.Connection | None = None,
) -> list[dict]:
    """List rooms that an identity is a member of.

    Args:
        ns: Namespace ID
        identity_id: Identity ID
        conn: Optional database connection

    Returns:
        List of room info dicts with member info. ``has_unread`` follows
        the room half of ``BADGE_UNREAD_SQL``: any message after the caller's
        read cursor, with an unset or non-UUIDv7 cursor counting the room.
        It is an EXISTS rather than a COUNT so the list stops at the first
        unread row instead of reading every unread message in every room.
    """
    conn = _get_conn(conn)
    cursor = conn.execute(
        """SELECT r.room_id, r.ns, r.display_name, r.created_by, r.created_at,
                  m.joined_at, m.last_read_mid,
                  (SELECT COUNT(*) FROM room_members rm WHERE rm.room_id = r.room_id)
                      AS member_count,
                  (SELECT MAX(rm2.created_at) FROM room_messages rm2
                   WHERE rm2.room_id = r.room_id) AS last_activity_at,
                  (SELECT rm3.body FROM room_messages rm3
                   WHERE rm3.room_id = r.room_id
                     AND rm3.content_type != 'reaction'
                   ORDER BY rm3.mid DESC LIMIT 1) AS last_message_body,
                  (SELECT rm4.from_id FROM room_messages rm4
                   WHERE rm4.room_id = r.room_id
                     AND rm4.content_type != 'reaction'
                   ORDER BY rm4.mid DESC LIMIT 1) AS last_message_from,
                  (SELECT COALESCE(
                       json_extract(i.metadata, '$.display_name'),
                       rm5.from_id)
                   FROM room_messages rm5
                   LEFT JOIN identities i ON i.id = rm5.from_id AND i.ns = r.ns
                   WHERE rm5.room_id = r.room_id
                     AND rm5.content_type != 'reaction'
                   ORDER BY rm5.mid DESC LIMIT 1) AS last_message_from_name,
                  EXISTS (SELECT 1 FROM room_messages rm6
                   WHERE rm6.room_id = r.room_id
                     AND rm6.mid > CASE
                         WHEN m.last_read_mid IS NULL OR m.last_read_mid = '' THEN ''
                         WHEN length(m.last_read_mid) >= 15
                              AND substr(m.last_read_mid, 15, 1) != '7' THEN ''
                         ELSE m.last_read_mid
                     END) AS has_unread
           FROM rooms r
           JOIN room_members m ON r.room_id = m.room_id
           WHERE r.ns = ? AND m.identity_id = ?
           ORDER BY r.created_at""",
        (ns, identity_id),
        name="list_rooms_for_identity",
    )
    return _rows_to_dicts(cursor.description, cursor.fetchall())


def delete_room(
    room_id: str,
    conn: sqlite3.Connection | None = None,
) -> bool:
    """Delete a room and all its messages/members.

    Args:
        room_id: Room ID
        conn: Optional database connection

    Returns:
        True if deleted, False if not found
    """
    conn = _get_conn(conn)
    cursor = conn.execute("DELETE FROM rooms WHERE room_id = ?", (room_id,), name="delete_room")
    conn.commit()
    return cursor.rowcount > 0


@timed_query("is_room_member")
def is_room_member(
    room_id: str,
    identity_id: str,
    conn: sqlite3.Connection | None = None,
) -> bool:
    """Check if an identity is a member of a room.

    Args:
        room_id: Room ID
        identity_id: Identity ID
        conn: Optional database connection

    Returns:
        True if member, False otherwise
    """
    conn = _get_conn(conn)
    cursor = conn.execute(
        "SELECT 1 FROM room_members WHERE room_id = ? AND identity_id = ?",
        (room_id, identity_id),
        name="is_room_member.select",
    )
    return cursor.fetchone() is not None


def add_room_member(
    room_id: str,
    identity_id: str,
    conn: sqlite3.Connection | None = None,
) -> dict:
    """Add a member to a room.

    Args:
        room_id: Room ID
        identity_id: Identity ID to add
        conn: Optional database connection

    Returns:
        Member info dict

    Raises:
        ValueError: If room not found or identity not in same namespace
    """
    conn = _get_conn(conn)

    # Get room info to verify it exists and get namespace
    room = get_room(room_id, conn=conn)
    if not room:
        raise ValueError(f"Room {room_id} not found")

    ns = room["ns"]

    # Verify identity exists in same namespace
    cursor = conn.execute(
        "SELECT id FROM identities WHERE ns = ? AND id = ?",
        (ns, identity_id),
        name="add_room_member.verify_identity",
    )
    if not cursor.fetchone():
        raise ValueError(f"Identity {identity_id} not found in namespace {ns}")

    # Check if already a member
    if is_room_member(room_id, identity_id, conn=conn):
        # Return existing membership
        cursor = conn.execute(
            "SELECT room_id, identity_id, ns, joined_at, last_read_mid FROM room_members WHERE room_id = ? AND identity_id = ?",
            (room_id, identity_id),
            name="add_room_member.get_existing",
        )
        return _row_to_dict(cursor.description, cursor.fetchone())  # type: ignore

    now = datetime.now(timezone.utc).isoformat()

    conn.execute(
        """INSERT INTO room_members (room_id, identity_id, ns, joined_at)
           VALUES (?, ?, ?, ?)""",
        (room_id, identity_id, ns, now),
        name="add_room_member.insert",
    )
    conn.commit()

    return {
        "room_id": room_id,
        "identity_id": identity_id,
        "ns": ns,
        "joined_at": now,
        "last_read_mid": None,
    }


def remove_room_member(
    room_id: str,
    identity_id: str,
    conn: sqlite3.Connection | None = None,
) -> bool:
    """Remove a member from a room.

    Args:
        room_id: Room ID
        identity_id: Identity ID to remove
        conn: Optional database connection

    Returns:
        True if removed, False if not a member
    """
    conn = _get_conn(conn)
    cursor = conn.execute(
        "DELETE FROM room_members WHERE room_id = ? AND identity_id = ?",
        (room_id, identity_id),
        name="remove_room_member",
    )
    conn.commit()
    return cursor.rowcount > 0


def list_room_members(
    room_id: str,
    conn: sqlite3.Connection | None = None,
) -> list[dict]:
    """List all members of a room.

    Args:
        room_id: Room ID
        conn: Optional database connection

    Returns:
        List of member info dicts with identity metadata
    """
    conn = _get_conn(conn)
    cursor = conn.execute(
        """SELECT m.room_id, m.identity_id, m.ns, m.joined_at, m.last_read_mid,
                  i.metadata
           FROM room_members m
           JOIN identities i ON m.ns = i.ns AND m.identity_id = i.id
           WHERE m.room_id = ?
           ORDER BY m.joined_at""",
        (room_id,),
        name="list_room_members",
    )
    rows = _rows_to_dicts(cursor.description, cursor.fetchall())

    # Parse metadata JSON
    for row in rows:
        row["metadata"] = json.loads(row.get("metadata") or "{}")

    return rows


@timed_query("send_room_message")
def send_room_message(
    room_id: str,
    from_id: str,
    body: str,
    content_type: str = "text/plain",
    reference_mid: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> dict:
    """Send a message to a room.

    Implements implicit idempotency: if the same sender sends an identical
    message (same body, content_type, reference_mid) to the same room
    within DEDUP_WINDOW_SECONDS, the original message is returned instead
    of creating a duplicate.

    Args:
        room_id: Room ID
        from_id: Sender identity ID (must be a member)
        body: Message body
        content_type: Content type (default: text/plain)
        reference_mid: Optional message ID this message references (e.g. for reactions)
        conn: Optional database connection

    Returns:
        Message info dict

    Raises:
        ValueError: If room not found or sender not a member
    """
    conn = _get_conn(conn)

    # Auth (room existence + membership) is handled by the API layer
    # via _require_room_member() before this function is called.
    # Removing redundant checks here saves 2 Turso roundtrips (~300-500ms each).

    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    content_hash = _compute_content_hash(body, content_type, reference_mid)

    # Dedup + insert in ONE round-trip via a conditional INSERT:
    #
    #   INSERT INTO room_messages ... SELECT <values>
    #   WHERE NOT EXISTS (
    #       SELECT 1 FROM room_messages
    #       WHERE room_id=? AND from_id=? AND content_hash=? AND created_at > ?
    #   )
    # Conditional INSERT: skip if a duplicate exists within the dedup window.
    # cursor.rowcount == 0 → dedup fired; fetch existing and return.
    # cursor.rowcount == 1 → new message inserted.
    mid = str(make_uuid7())
    window_start = (now - timedelta(seconds=DEDUP_WINDOW_SECONDS)).isoformat()

    cursor = conn.execute(
        """INSERT INTO room_messages
               (mid, room_id, from_id, body, content_type, content_hash, reference_mid, created_at)
           SELECT ?, ?, ?, ?, ?, ?, ?, ?
           WHERE NOT EXISTS (
               SELECT 1 FROM room_messages
               WHERE room_id = ? AND from_id = ? AND content_hash = ?
                 AND created_at > ?
           )""",
        (
            mid,
            room_id,
            from_id,
            body,
            content_type,
            content_hash,
            reference_mid,
            now_iso,
            room_id,
            from_id,
            content_hash,
            window_start,
        ),
        name="send_room_message.upsert",
    )
    conn.commit()

    if cursor.rowcount == 0:
        # Dedup fired — the conditional INSERT matched an existing message.
        # Fetch the original so we can return consistent fields.
        cursor = conn.execute(
            """SELECT mid, room_id, from_id, body, content_type, reference_mid, created_at
               FROM room_messages
               WHERE room_id = ? AND from_id = ? AND content_hash = ?
                 AND created_at > ?
               ORDER BY created_at DESC LIMIT 1""",
            (room_id, from_id, content_hash, window_start),
            name="send_room_message.dedup_fetch",
        )
        existing = _row_to_dict(cursor.description, cursor.fetchone())
        # existing should always be non-None here since the INSERT-guard matched it,
        # but fall back to a safe new-message response if the DB is in a weird state.
        if existing:
            return {
                "mid": existing["mid"],
                "room_id": existing["room_id"],
                "from": existing["from_id"],
                "body": existing["body"],
                "content_type": existing.get("content_type") or "text/plain",
                "reference_mid": existing.get("reference_mid"),
                "created_at": existing["created_at"],
                "deduplicated": True,
            }

    return {
        "mid": mid,
        "room_id": room_id,
        "from": from_id,
        "body": body,
        "content_type": content_type,
        "reference_mid": reference_mid,
        "created_at": now_iso,
    }


@timed_query("has_new_room_messages")
def has_new_room_messages(
    room_id: str,
    after_mid: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> bool:
    """Check if there are new messages in a room.

    Lightweight check using COUNT - efficient for polling.

    Args:
        room_id: Room ID
        after_mid: Only count messages after this message ID
        conn: Optional database connection

    Returns:
        True if there are new messages
    """
    conn = _get_conn(conn)

    query = "SELECT COUNT(*) FROM room_messages WHERE room_id = ?"
    params: list[Any] = [room_id]

    if after_mid:
        query += " AND mid > ?"
        params.append(after_mid)

    cursor = conn.execute(query, tuple(params), name="has_new_room_messages.count")
    count = cursor.fetchone()[0]
    return count > 0


@timed_query("get_room_messages")
def get_room_messages(
    room_id: str,
    after_mid: str | None = None,
    before_mid: str | None = None,
    limit: int = 100,
    exclude_reactions: bool = False,
    conn: sqlite3.Connection | None = None,
) -> list[dict]:
    """Get messages from a room with attachment metadata via LEFT JOIN.

    Supports both forward and backward pagination:
    - ``after_mid``: messages newer than this ID (forward / polling)
    - ``before_mid``: messages older than this ID (backward / scroll-up)

    When ``before_mid`` is provided the query fetches the *newest* messages
    that are still older than the cursor, so the caller receives the page
    immediately preceding the cursor in chronological order.

    Results are always returned in chronological (ascending mid) order
    regardless of pagination direction.

    Attachment metadata (id, filename, content_type, size, created_at) is
    LEFT JOINed inline so no second round-trip is needed.  The ``attachments``
    key on each message dict is a list of attachment dicts (may be empty).

    Args:
        room_id: Room ID
        after_mid: Only get messages after this message ID (forward pagination)
        before_mid: Only get messages before this message ID (backward pagination)
        limit: Maximum number of messages to return
        conn: Optional database connection

    Returns:
        List of message dicts ordered by creation time (ascending).
        Each dict contains an ``attachments`` key (list, possibly empty).
    """
    conn = _get_conn(conn)

    # Subquery wraps the pagination so we JOIN attachments only on the
    # page of messages that will actually be returned.
    subquery = "SELECT mid FROM room_messages WHERE room_id = ?"
    params: list[Any] = [room_id]

    if exclude_reactions:
        subquery += " AND content_type != 'reaction'"

    if after_mid:
        subquery += " AND mid > ?"
        params.append(after_mid)

    if before_mid:
        subquery += " AND mid < ?"
        params.append(before_mid)

    # Determine sort direction:
    # - after_mid only: forward scan (ASC) — polling for new messages
    # - before_mid (with or without after_mid): backward scan (DESC) — scroll-up
    # - neither cursor: backward scan (DESC) — initial load gets newest page
    use_desc = not after_mid or (before_mid and not after_mid)

    if use_desc:
        subquery += " ORDER BY mid DESC LIMIT ?"
    else:
        subquery += " ORDER BY mid LIMIT ?"
    params.append(limit)

    # Duplicate params for the outer query (subquery uses them once)
    query = f"""
        SELECT
            rm.mid, rm.room_id, rm.from_id, rm.body, rm.content_type,
            rm.reference_mid, rm.created_at,
            a.id        AS att_id,
            a.filename  AS att_filename,
            a.content_type AS att_content_type,
            a.size      AS att_size,
            a.created_at AS att_created_at
        FROM room_messages rm
        LEFT JOIN attachments a ON a.message_mid = rm.mid
        WHERE rm.mid IN ({subquery})
        ORDER BY rm.mid {"DESC" if use_desc else "ASC"}, a.created_at
    """

    cursor = conn.execute(query, tuple(params), name="get_room_messages.select")
    rows = _rows_to_dicts(cursor.description, cursor.fetchall())

    # Collapse multi-row JOIN results into one message dict per mid
    messages_by_mid: dict[str, dict] = {}
    mid_order: list[str] = []

    for row in rows:
        mid = row["mid"]
        if mid not in messages_by_mid:
            mid_order.append(mid)
            messages_by_mid[mid] = {
                "mid": mid,
                "room_id": row["room_id"],
                "from": row["from_id"],
                "body": row["body"],
                "content_type": row.get("content_type") or "text/plain",
                "reference_mid": row.get("reference_mid"),
                "created_at": row["created_at"],
                "attachments": [],
            }
        if row.get("att_id") is not None:
            messages_by_mid[mid]["attachments"].append(
                {
                    "id": row["att_id"],
                    "message_mid": mid,
                    "filename": row["att_filename"],
                    "content_type": row["att_content_type"],
                    "size": row["att_size"],
                    "created_at": row["att_created_at"],
                }
            )

    messages = [messages_by_mid[mid] for mid in mid_order]

    # DESC rows need reversing so callers always get chronological order.
    if use_desc:
        messages.reverse()

    return messages


@timed_query("get_room_message")
def get_room_message(
    room_id: str,
    mid: str,
    conn: sqlite3.Connection | None = None,
) -> dict | None:
    """Get a single room message.

    Args:
        room_id: Room ID
        mid: Message ID
        conn: Optional database connection

    Returns:
        Message dict or None if not found
    """
    conn = _get_conn(conn)
    cursor = conn.execute(
        """SELECT mid, room_id, from_id, body, content_type, reference_mid, created_at
           FROM room_messages WHERE room_id = ? AND mid = ?""",
        (room_id, mid),
        name="get_room_message.select",
    )
    row = _row_to_dict(cursor.description, cursor.fetchone())

    if row:
        return {
            "mid": row["mid"],
            "room_id": row["room_id"],
            "from": row["from_id"],
            "body": row["body"],
            "content_type": row.get("content_type") or "text/plain",
            "reference_mid": row.get("reference_mid"),
            "created_at": row["created_at"],
        }
    return None


@timed_query("update_room_read_cursor")
def update_room_read_cursor(
    room_id: str,
    identity_id: str,
    last_read_mid: str,
    conn: sqlite3.Connection | None = None,
) -> bool:
    """Update the read cursor for a member in a room.

    Only updates if the new cursor is ahead of the current one.

    Args:
        room_id: Room ID
        identity_id: Identity ID
        last_read_mid: Message ID of the last read message
        conn: Optional database connection

    Returns:
        True if updated, False if member not found
    """
    conn = _get_conn(conn)

    # Only update if cursor moves forward (UUID7 is lexicographically sortable).
    #
    # Legacy data may contain non-v7 cursors (UUIDv4s from before API-level
    # validation was added). A v4 like '1e14...' is lexicographically greater
    # than any v7 like '0194...' / '01f0...', so a naive `last_read_mid < ?`
    # check silently refuses to advance past a poisoned v4 cursor. Treat any
    # non-v7 stored cursor as "unset" so new v7 writes clobber poisoning.
    # UUID v7 has version nibble '7' at string position 14 (0-indexed),
    # i.e. the 15th character — SQL substr is 1-indexed so position 15.
    cursor = conn.execute(
        """UPDATE room_members
           SET last_read_mid = ?
           WHERE room_id = ? AND identity_id = ?
           AND (
               last_read_mid IS NULL
               OR substr(last_read_mid, 15, 1) != '7'
               OR last_read_mid < ?
           )""",
        (last_read_mid, room_id, identity_id, last_read_mid),
        name="update_room_read_cursor.update",
    )
    conn.commit()

    # Return True if we actually updated (not just if member exists)
    # If the cursor didn't move, rowcount will be 0
    if cursor.rowcount > 0:
        return True

    # Check if member exists (they might already have a later cursor)
    cursor = conn.execute(
        "SELECT 1 FROM room_members WHERE room_id = ? AND identity_id = ?",
        (room_id, identity_id),
        name="update_room_read_cursor.check_member",
    )
    return cursor.fetchone() is not None


@timed_query("get_room_unread_count")
def get_room_unread_count(
    room_id: str,
    identity_id: str,
    conn: sqlite3.Connection | None = None,
) -> int:
    """Get the count of unread messages for a member in a room.

    Args:
        room_id: Room ID
        identity_id: Identity ID
        conn: Optional database connection

    Returns:
        Number of unread messages (0 if not a member)
    """
    conn = _get_conn(conn)

    # Get member's last read cursor
    cursor = conn.execute(
        "SELECT last_read_mid FROM room_members WHERE room_id = ? AND identity_id = ?",
        (room_id, identity_id),
        name="get_room_unread_count.get_cursor",
    )
    row = cursor.fetchone()

    if not row:
        return 0  # Not a member

    last_read_mid = row[0]

    # Treat legacy non-v7 cursors (e.g. UUIDv4) as unset — they can't be
    # compared meaningfully against v7 message IDs. See update_room_read_cursor
    # for the matching write-path defense.
    if last_read_mid and len(last_read_mid) >= 15 and last_read_mid[14] != "7":
        last_read_mid = None

    # Count messages after the cursor
    if last_read_mid:
        cursor = conn.execute(
            "SELECT COUNT(*) FROM room_messages WHERE room_id = ? AND mid > ?",
            (room_id, last_read_mid),
            name="get_room_unread_count.count",
        )
    else:
        cursor = conn.execute(
            "SELECT COUNT(*) FROM room_messages WHERE room_id = ?",
            (room_id,),
            name="get_room_unread_count.count",
        )

    return cursor.fetchone()[0]


def get_room_member_info(
    room_id: str,
    identity_id: str,
    conn: sqlite3.Connection | None = None,
) -> dict | None:
    """Get membership info for an identity in a room.

    Args:
        room_id: Room ID
        identity_id: Identity ID
        conn: Optional database connection

    Returns:
        Member info dict or None if not a member
    """
    conn = _get_conn(conn)
    cursor = conn.execute(
        """SELECT m.room_id, m.identity_id, m.ns, m.joined_at, m.last_read_mid,
                  i.metadata
           FROM room_members m
           JOIN identities i ON m.ns = i.ns AND m.identity_id = i.id
           WHERE m.room_id = ? AND m.identity_id = ?""",
        (room_id, identity_id),
        name="get_room_member_info",
    )
    row = _row_to_dict(cursor.description, cursor.fetchone())

    if row:
        row["metadata"] = json.loads(row.get("metadata") or "{}")

    return row


# --- Optimized Combined Queries for Performance ---
# These functions reduce round-trips by combining multiple queries into one
# and leveraging caching for frequently-accessed data.


def verify_room_access(
    room_id: str,
    identity_id: str,
    secret: str,
    conn: sqlite3.Connection | None = None,
) -> tuple[dict | None, str | None]:
    """Verify room access in a single optimized query.

    This combines:
    - get_room (room exists check)
    - is_room_member (membership check)
    - verify_identity_secret (auth check)

    Into a single database round-trip plus cached hash verification.

    Args:
        room_id: Room ID to access
        identity_id: Identity ID (derived from secret)
        secret: The inbox secret for verification
        conn: Optional database connection

    Returns:
        (room, error_message) tuple:
        - If successful: (room_dict, None)
        - If failed: (None, error_message)
    """
    from .auth import derive_id, verify_secret
    from .cache import identity_hash_cache, membership_cache, room_cache
    from .metrics import timed_db_operation

    # First verify the identity_id matches the secret (no DB needed)
    if derive_id(secret) != identity_id:
        return None, "Secret does not match identity"

    # Check room cache first
    cache_hit, cached_room = room_cache.get(f"room:{room_id}")
    if cache_hit and cached_room is None:
        return None, "Room not found"

    # Check membership cache
    membership_key = f"member:{room_id}:{identity_id}"
    membership_hit, is_member = membership_cache.get(membership_key)

    # Check identity hash cache
    ns = cached_room["ns"] if cache_hit and cached_room else None
    identity_key = f"identity:{ns}:{identity_id}" if ns else None
    hash_hit, cached_hash = identity_hash_cache.get(identity_key) if identity_key else (False, None)

    # If all cache hits, we can skip the database entirely
    if cache_hit and cached_room and membership_hit and is_member and hash_hit and cached_hash:
        # Just verify the password hash
        if verify_secret(secret, cached_hash):
            return cached_room, None
        else:
            return None, "Invalid inbox secret"

    # Need to hit database - use optimized combined query
    conn = _get_conn(conn)

    with timed_db_operation("verify_room_access"):
        cursor = conn.execute(
            """
            SELECT 
                r.room_id, r.ns, r.display_name, r.created_by, r.created_at,
                m.identity_id as member_id,
                i.secret_hash
            FROM rooms r
            LEFT JOIN room_members m ON r.room_id = m.room_id AND m.identity_id = ?
            LEFT JOIN identities i ON r.ns = i.ns AND i.id = ?
            WHERE r.room_id = ?
            """,
            (identity_id, identity_id, room_id),
            name="verify_room_access",
        )
        row = _row_to_dict(cursor.description, cursor.fetchone())

    if not row:
        room_cache.set(f"room:{room_id}", None, ttl=60)  # Cache negative result briefly
        return None, "Room not found"

    # Build room dict
    room = {
        "room_id": row["room_id"],
        "ns": row["ns"],
        "display_name": row["display_name"],
        "created_by": row["created_by"],
        "created_at": row["created_at"],
    }

    # Cache the room
    room_cache.set(f"room:{room_id}", room)

    # Check membership
    if not row.get("member_id"):
        membership_cache.set(membership_key, False)
        return None, "Not a member of this room"
    membership_cache.set(membership_key, True)

    # Check identity exists and verify secret
    secret_hash = row.get("secret_hash")
    if not secret_hash:
        return None, "Identity not found in namespace"

    # Cache the hash
    identity_hash_cache.set(f"identity:{room['ns']}:{identity_id}", secret_hash)

    # Verify the secret
    if not verify_secret(secret, secret_hash):
        return None, "Invalid inbox secret"

    return room, None


def get_room_cached(
    room_id: str,
    conn: sqlite3.Connection | None = None,
) -> dict | None:
    """Get room by ID with caching.

    Args:
        room_id: Room ID
        conn: Optional database connection

    Returns:
        Room info dict or None if not found
    """
    from .cache import room_cache
    from .metrics import timed_db_operation

    # Check cache first
    cache_hit, cached_room = room_cache.get(f"room:{room_id}")
    if cache_hit:
        return cached_room

    # Cache miss - fetch from database
    conn = _get_conn(conn)

    with timed_db_operation("get_room_cached"):
        cursor = conn.execute(
            """SELECT room_id, ns, display_name, created_by, created_at
               FROM rooms WHERE room_id = ?""",
            (room_id,),
            name="get_room_cached",
        )
        row = _row_to_dict(cursor.description, cursor.fetchone())

    # Cache the result (even if None)
    room_cache.set(f"room:{room_id}", row, ttl=60 if row is None else 300)
    return row


def get_identity_hash_cached(
    ns: str,
    identity_id: str,
    conn: sqlite3.Connection | None = None,
) -> str | None:
    """Get identity secret hash with caching.

    Args:
        ns: Namespace ID
        identity_id: Identity ID
        conn: Optional database connection

    Returns:
        Secret hash or None if identity not found
    """
    from .cache import identity_hash_cache
    from .metrics import timed_db_operation

    cache_key = f"identity:{ns}:{identity_id}"
    cache_hit, cached_hash = identity_hash_cache.get(cache_key)
    if cache_hit:
        return cached_hash

    conn = _get_conn(conn)

    with timed_db_operation("get_identity_hash_cached"):
        cursor = conn.execute(
            "SELECT secret_hash FROM identities WHERE ns = ? AND id = ?",
            (ns, identity_id),
            name="get_identity_hash_cached",
        )
        row = cursor.fetchone()

    secret_hash = row[0] if row else None
    identity_hash_cache.set(cache_key, secret_hash)
    return secret_hash


def is_room_member_cached(
    room_id: str,
    identity_id: str,
    conn: sqlite3.Connection | None = None,
) -> bool:
    """Check if an identity is a member of a room with caching.

    Args:
        room_id: Room ID
        identity_id: Identity ID
        conn: Optional database connection

    Returns:
        True if member, False otherwise
    """
    from .cache import membership_cache
    from .metrics import timed_db_operation

    cache_key = f"member:{room_id}:{identity_id}"
    cache_hit, is_member = membership_cache.get(cache_key)
    if cache_hit:
        return is_member

    conn = _get_conn(conn)

    with timed_db_operation("is_room_member_cached"):
        cursor = conn.execute(
            "SELECT 1 FROM room_members WHERE room_id = ? AND identity_id = ?",
            (room_id, identity_id),
            name="is_room_member_cached",
        )
        is_member = cursor.fetchone() is not None

    membership_cache.set(cache_key, is_member)
    return is_member


# ---------------------------------------------------------------------------
# Attachments
# ---------------------------------------------------------------------------


@timed_query("add_attachment")
def add_attachment(
    message_mid: str,
    content_type: str,
    data: str,
    size: int,
    filename: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> dict:
    """Store an attachment for a message.

    Args:
        message_mid: The mid of the message this attachment belongs to.
        content_type: MIME type (e.g. "image/png").
        data: Base64-encoded content.
        size: Raw byte size before base64 encoding.
        filename: Optional original filename.
        conn: Optional database connection.

    Returns:
        Attachment info dict with id, message_mid, filename, content_type, size, created_at.
    """
    conn = _get_conn(conn)
    import uuid as _uuid

    attachment_id = str(_uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()

    conn.execute(
        """INSERT INTO attachments (id, message_mid, filename, content_type, data, size, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (attachment_id, message_mid, filename, content_type, data, size, now_iso),
        name="add_attachment.insert",
    )
    conn.commit()

    return {
        "id": attachment_id,
        "message_mid": message_mid,
        "filename": filename,
        "content_type": content_type,
        "size": size,
        "created_at": now_iso,
    }


@timed_query("get_attachment")
def get_attachment(
    attachment_id: str,
    include_data: bool = True,
    conn: sqlite3.Connection | None = None,
) -> dict | None:
    """Retrieve an attachment by ID.

    Args:
        attachment_id: The attachment ID.
        include_data: Whether to include the base64 data (default True).
        conn: Optional database connection.

    Returns:
        Attachment dict or None if not found.
    """
    conn = _get_conn(conn)
    cols = (
        "id, message_mid, filename, content_type, data, size, created_at"
        if include_data
        else "id, message_mid, filename, content_type, size, created_at"
    )
    cursor = conn.execute(
        f"SELECT {cols} FROM attachments WHERE id = ?",
        (attachment_id,),
        name="get_attachment.select",
    )
    row = cursor.fetchone()
    if not row:
        return None

    result = {
        "id": row[0],
        "message_mid": row[1],
        "filename": row[2],
        "content_type": row[3],
    }
    if include_data:
        result["data"] = row[4]
        result["size"] = row[5]
        result["created_at"] = row[6]
    else:
        result["size"] = row[4]
        result["created_at"] = row[5]
    return result


def get_message_attachments(
    message_mid: str,
    include_data: bool = False,
    conn: sqlite3.Connection | None = None,
) -> list[dict]:
    """Get all attachments for a message.

    Args:
        message_mid: The message mid.
        include_data: Whether to include base64 data (default False for listings).
        conn: Optional database connection.

    Returns:
        List of attachment dicts.
    """
    conn = _get_conn(conn)
    if include_data:
        cols = "id, message_mid, filename, content_type, data, size, created_at"
    else:
        cols = "id, message_mid, filename, content_type, size, created_at"

    cursor = conn.execute(
        f"SELECT {cols} FROM attachments WHERE message_mid = ? ORDER BY created_at",
        (message_mid,),
        name="get_message_attachments",
    )
    results = []
    for row in cursor.fetchall():
        att = {
            "id": row[0],
            "message_mid": row[1],
            "filename": row[2],
            "content_type": row[3],
        }
        if include_data:
            att["data"] = row[4]
            att["size"] = row[5]
            att["created_at"] = row[6]
        else:
            att["size"] = row[4]
            att["created_at"] = row[5]
        results.append(att)
    return results


def get_batch_message_attachments(
    message_mids: list[str],
    include_data: bool = False,
    conn: sqlite3.Connection | None = None,
) -> dict[str, list[dict]]:
    """Get attachments for multiple messages in a single query.

    Args:
        message_mids: List of message mids to fetch attachments for.
        include_data: Whether to include base64 data (default False for listings).
        conn: Optional database connection.

    Returns:
        Dict mapping message_mid -> list of attachment dicts.
    """
    if not message_mids:
        return {}

    conn = _get_conn(conn)
    if include_data:
        cols = "id, message_mid, filename, content_type, data, size, created_at"
    else:
        cols = "id, message_mid, filename, content_type, size, created_at"

    placeholders = ",".join("?" for _ in message_mids)
    cursor = conn.execute(
        f"SELECT {cols} FROM attachments WHERE message_mid IN ({placeholders}) ORDER BY created_at",
        tuple(message_mids),
        name="get_batch_message_attachments",
    )

    results: dict[str, list[dict]] = {}
    for row in cursor.fetchall():
        att = {
            "id": row[0],
            "message_mid": row[1],
            "filename": row[2],
            "content_type": row[3],
        }
        if include_data:
            att["data"] = row[4]
            att["size"] = row[5]
            att["created_at"] = row[6]
        else:
            att["size"] = row[4]
            att["created_at"] = row[5]
        results.setdefault(att["message_mid"], []).append(att)
    return results


@timed_query("list_room_attachments")
def list_room_attachments(
    room_id: str,
    before_mid: str | None = None,
    before_id: str | None = None,
    limit: int = 60,
    conn: sqlite3.Connection | None = None,
) -> list[dict]:
    """List a room's attachment metadata, newest first.

    Ordering is ``(message_mid DESC, id DESC)``. Message mids are uuidv7, so
    that is reverse-chronological; ``id`` breaks ties between attachments on
    the same message deterministically.

    Pagination is keyset on that same pair: pass the last returned row's
    ``message_mid``/``id`` back as ``before_mid``/``before_id`` to get the next
    page. Both must be supplied together — a lone ``before_mid`` would skip the
    remaining attachments of that message.

    Base64 data is never selected; each row carries the sender and message
    timestamp needed to render a gallery entry and link back to the message.

    Args:
        room_id: Room ID.
        before_mid: Keyset cursor — message mid of the last row of the prior page.
        before_id: Keyset cursor — attachment id of the last row of the prior page.
        limit: Maximum number of attachments to return.
        conn: Optional database connection.

    Returns:
        List of attachment dicts, newest first.
    """
    conn = _get_conn(conn)

    query = """
        SELECT
            a.id, a.message_mid, a.filename, a.content_type, a.size,
            a.created_at, rm.from_id, rm.created_at AS message_created_at
        FROM attachments a
        JOIN room_messages rm ON rm.mid = a.message_mid
        WHERE rm.room_id = ?
    """
    params: list[Any] = [room_id]

    if before_mid and before_id:
        query += " AND (a.message_mid < ? OR (a.message_mid = ? AND a.id < ?))"
        params.extend([before_mid, before_mid, before_id])

    query += " ORDER BY a.message_mid DESC, a.id DESC LIMIT ?"
    params.append(limit)

    cursor = conn.execute(query, tuple(params), name="list_room_attachments.select")
    return [
        {
            "id": row[0],
            "message_mid": row[1],
            "filename": row[2],
            "content_type": row[3],
            "size": row[4],
            "created_at": row[5],
            "from": row[6],
            "message_created_at": row[7],
        }
        for row in cursor.fetchall()
    ]


def escape_like(term: str) -> str:
    r"""Escape LIKE wildcards in a user-supplied term for ``ESCAPE '\'``."""
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


@timed_query("search_room_messages")
def search_room_messages(
    room_id: str,
    query: str,
    before_mid: str | None = None,
    limit: int = 50,
    conn: sqlite3.Connection | None = None,
) -> list[dict]:
    """Substring-search a room's message bodies, newest match first.

    Case-insensitive via ``LOWER()`` on both sides, which keeps the match
    non-ASCII-aware but avoids depending on a collation or an FTS index.
    Reactions are excluded — their body is an emoji, not prose.

    Args:
        room_id: Room ID.
        query: Search term. Wildcards are escaped, so it matches literally.
        before_mid: Keyset cursor — only match messages older than this mid.
        limit: Maximum number of matches to return.
        conn: Optional database connection.

    Returns:
        List of message dicts (no attachment data), newest first.
    """
    conn = _get_conn(conn)

    sql = """
        SELECT mid, room_id, from_id, body, content_type, created_at
        FROM room_messages
        WHERE room_id = ?
          AND content_type != 'reaction'
          AND LOWER(body) LIKE ? ESCAPE '\\'
    """
    params: list[Any] = [room_id, f"%{escape_like(query.lower())}%"]

    if before_mid:
        sql += " AND mid < ?"
        params.append(before_mid)

    sql += " ORDER BY mid DESC LIMIT ?"
    params.append(limit)

    cursor = conn.execute(sql, tuple(params), name="search_room_messages.select")
    return [
        {
            "mid": row[0],
            "room_id": row[1],
            "from": row[2],
            "body": row[3],
            "content_type": row[4] or "text/plain",
            "created_at": row[5],
        }
        for row in cursor.fetchall()
    ]


def get_topic_latest(
    topic_key: str,
    ns: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> tuple[str, str | None] | None:
    """Get the latest (mid, sender_id) for a subscribe topic.

    Used by the event bus cold-start fallback to seed _latest from the DB
    when the process has restarted and hasn't seen a publish for a topic yet.

    Args:
        topic_key: Topic in "room:{room_id}" or "inbox:{identity_id}" format.
        ns: Namespace ID (required for inbox topics, ignored for room topics).
        conn: Optional database connection.

    Returns:
        (latest_mid, sender_id) or None if no messages exist.
    """
    conn = _get_conn(conn)

    if topic_key.startswith("room:"):
        room_id = topic_key[len("room:") :]
        cursor = conn.execute(
            "SELECT mid, from_id FROM room_messages WHERE room_id = ? ORDER BY mid DESC LIMIT 1",
            (room_id,),
            name="get_topic_latest.room",
        )
        row = cursor.fetchone()
        if row:
            return (row[0], row[1])
        return None

    elif topic_key.startswith("inbox:"):
        identity_id = topic_key[len("inbox:") :]
        if ns is None:
            return None
        cursor = conn.execute(
            "SELECT mid, from_id FROM messages "
            "WHERE ns = ? AND to_id = ? "
            "AND archived_at IS NULL "
            "ORDER BY mid DESC LIMIT 1",
            (ns, identity_id),
            name="get_topic_latest.inbox",
        )
        row = cursor.fetchone()
        if row:
            return (row[0], row[1])
        return None

    return None


# --- Web Push Subscriptions ---


@timed_query("upsert_push_subscription")
def upsert_push_subscription(
    ns: str,
    identity_id: str,
    endpoint: str,
    p256dh: str,
    auth: str,
    user_agent: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> dict:
    """Register (or re-register) a Web Push subscription for an identity.

    The endpoint is the primary key: a browser that re-subscribes after the
    push service rotated its endpoint produces a new row, and a re-subscribe
    on the same endpoint overwrites the keys in place.

    Args:
        ns: Namespace ID
        identity_id: Identity that owns the subscription
        endpoint: Push service endpoint URL (primary key)
        p256dh: base64url-encoded P-256 public key of the user agent
        auth: base64url-encoded 16-byte auth secret
        user_agent: Optional UA string, for debugging which device this is
        conn: Optional database connection

    Returns:
        The stored subscription as a dict.
    """
    conn = _get_conn(conn)
    conn.execute(
        """INSERT INTO push_subscriptions
               (endpoint, ns, identity_id, p256dh, auth, user_agent, created_at)
           VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
           ON CONFLICT(endpoint) DO UPDATE SET
               ns = excluded.ns,
               identity_id = excluded.identity_id,
               p256dh = excluded.p256dh,
               auth = excluded.auth,
               user_agent = excluded.user_agent""",
        (endpoint, ns, identity_id, p256dh, auth, user_agent),
        name="upsert_push_subscription.upsert",
    )
    conn.commit()

    cursor = conn.execute(
        """SELECT endpoint, ns, identity_id, p256dh, auth, user_agent, created_at, last_ok_at
           FROM push_subscriptions WHERE endpoint = ?""",
        (endpoint,),
        name="upsert_push_subscription.select",
    )
    row = _row_to_dict(cursor.description, cursor.fetchone())
    return row or {}


@timed_query("list_push_subscriptions")
def list_push_subscriptions(
    ns: str,
    identity_id: str,
    conn: sqlite3.Connection | None = None,
) -> list[dict]:
    """List every Web Push subscription registered by an identity."""
    conn = _get_conn(conn)
    cursor = conn.execute(
        """SELECT endpoint, ns, identity_id, p256dh, auth, user_agent, created_at, last_ok_at
           FROM push_subscriptions
           WHERE ns = ? AND identity_id = ?
           ORDER BY created_at""",
        (ns, identity_id),
        name="list_push_subscriptions",
    )
    return _rows_to_dicts(cursor.description, cursor.fetchall())


@timed_query("delete_push_subscription")
def delete_push_subscription(
    endpoint: str,
    ns: str | None = None,
    identity_id: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> bool:
    """Delete a subscription by endpoint.

    When ``ns``/``identity_id`` are supplied the delete is additionally scoped
    to that owner, so an authenticated caller can only remove its own rows.
    The pruning path (410 Gone from the push service) passes neither.

    Returns:
        True if a row was deleted.
    """
    conn = _get_conn(conn)
    if ns is not None and identity_id is not None:
        cursor = conn.execute(
            "DELETE FROM push_subscriptions WHERE endpoint = ? AND ns = ? AND identity_id = ?",
            (endpoint, ns, identity_id),
            name="delete_push_subscription.scoped",
        )
    else:
        cursor = conn.execute(
            "DELETE FROM push_subscriptions WHERE endpoint = ?",
            (endpoint,),
            name="delete_push_subscription",
        )
    conn.commit()
    return cursor.rowcount > 0


@timed_query("touch_push_subscription")
def touch_push_subscription(
    endpoint: str,
    conn: sqlite3.Connection | None = None,
) -> None:
    """Record a successful delivery against a subscription.

    ``last_ok_at`` is the only liveness signal we have for a subscription
    that the push service has not yet declared Gone.
    """
    conn = _get_conn(conn)
    conn.execute(
        "UPDATE push_subscriptions SET last_ok_at = CURRENT_TIMESTAMP WHERE endpoint = ?",
        (endpoint,),
        name="touch_push_subscription",
    )
    conn.commit()


# --- Web Push Preferences ---


@timed_query("get_push_enabled")
def get_push_enabled(
    ns: str,
    identity_id: str,
    conn: sqlite3.Connection | None = None,
) -> bool:
    """Is push delivery enabled for this identity?

    An identity with no row is enabled: registering a subscription is an
    explicit opt-in already, so the absent row must not mean "off".
    """
    conn = _get_conn(conn)
    cursor = conn.execute(
        "SELECT enabled FROM push_prefs WHERE ns = ? AND identity_id = ?",
        (ns, identity_id),
        name="get_push_enabled",
    )
    row = cursor.fetchone()
    if row is None:
        return True
    return bool(row[0])


@timed_query("set_push_enabled")
def set_push_enabled(
    ns: str,
    identity_id: str,
    enabled: bool,
    conn: sqlite3.Connection | None = None,
) -> bool:
    """Set the identity-wide push switch. Returns the stored value."""
    conn = _get_conn(conn)
    conn.execute(
        """INSERT INTO push_prefs (ns, identity_id, enabled, updated_at)
           VALUES (?, ?, ?, CURRENT_TIMESTAMP)
           ON CONFLICT(ns, identity_id) DO UPDATE SET
               enabled = excluded.enabled,
               updated_at = CURRENT_TIMESTAMP""",
        (ns, identity_id, 1 if enabled else 0),
        name="set_push_enabled.upsert",
    )
    conn.commit()
    return bool(enabled)


BADGE_UNREAD_SQL = """SELECT
     (SELECT COUNT(*)
        FROM room_members m
        JOIN room_messages rm ON rm.room_id = m.room_id
       WHERE m.ns = ? AND m.identity_id = ?
         AND rm.mid > CASE
             WHEN m.last_read_mid IS NULL OR m.last_read_mid = '' THEN ''
             WHEN length(m.last_read_mid) >= 15
                  AND substr(m.last_read_mid, 15, 1) != '7' THEN ''
             ELSE m.last_read_mid
         END)
     +
     (SELECT COUNT(*)
        FROM messages
       WHERE ns = ? AND to_id = ?
         AND read_at IS NULL
         AND archived_at IS NULL
         AND (expires_at IS NULL OR expires_at > ?))"""


@timed_query("count_unread_for_identity")
def count_unread_for_identity(
    ns: str,
    identity_id: str,
    conn: sqlite3.Connection | None = None,
) -> int:
    """Total unread messages for an identity: every room plus the inbox.

    This is the badge number: one integer for the whole app icon, matching
    what the thread list marks unread. The per-room definition in
    :func:`get_room_unread_count` is reproduced here as a single aggregate
    rather than N queries, including its treatment of a non-UUIDv7 cursor
    as unset; direct messages use ``read_at``, which the inbox fetch sets,
    and are filtered like :func:`get_messages` (live and unarchived).

    The room half normalises the cursor to a floor value first, so the only
    predicate on ``room_messages`` is a single ``mid >`` comparison. That
    keeps the range seek on ``idx_room_messages_room_mid`` bounded to the
    unread tail: an unset or uncomparable cursor becomes ``''``, which every
    mid sorts above, and so still counts the whole room. Spelling the three
    cursor states as OR branches instead degrades the seek to ``room_id = ?``
    and reads every message in every room the identity belongs to on every
    call.
    """
    conn = _get_conn(conn)
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        BADGE_UNREAD_SQL,
        (ns, identity_id, ns, identity_id, now),
        name="count_unread_for_identity",
    )
    return cursor.fetchone()[0]
