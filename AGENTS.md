# AGENTS.md — deaddrop

Project-level instructions for agents working on this repo. Read this before making changes.

---

## 🚦 CI Requirements — Always Run Before Pushing

```bash
uv run ruff check . && uv run ruff format --check .
```

If ruff format --check fails, run `uv run ruff format .` to fix, then re-check. **Do not push with linting errors.**

Run the test suite:

```bash
uv run pytest tests/ -q --timeout=30
```

---

## 🧪 Testing Strategy

### Client-Side Changes (HTML/JS/CSS)
Any change to the web client **must be tested in a browser with Playwright before PRing**:

```bash
# Start local server
uv run uvicorn deadrop.app:app --port 8001 --reload

# Run client tests
uv run pytest tests/test_client.py -q --timeout=30
```

Visually verify the change works — don't assume CSS changes are correct without rendering them.

### API / Backend Changes
```bash
uv run pytest tests/ -q --timeout=30
```

Focus areas by file:
- `tests/test_api.py` — REST API behavior
- `tests/test_rooms.py` / `tests/test_rooms_api.py` — room semantics
- `tests/test_instrumented_connection.py` — DB instrumentation
- `tests/test_attachments.py` — attachment upload/retrieval

---

## 🗄️ Database Layer

### Turso Write Latency
Production Turso latency profile (same-region):
- **Write path:** ~154ms end-to-end
- **Commit latency:** ~300–400ms (Raft consensus on multi-node)
- **Read path:** ~1–2ms (local replica reads)

Don't treat write latency as a bug to fix without first confirming you're measuring the right path. Check `InstrumentedConnection` slow query logs first.

### InstrumentedConnection — Always Use Named Queries
All DB operations must use `InstrumentedConnection` with explicit query names:

```python
# CORRECT — named query for metrics/tracing
conn.execute("SELECT_ROOM_MESSAGES", "SELECT * FROM messages WHERE room_id = ?", (room_id,))

# WRONG — anonymous query, no instrumentation
conn.execute("SELECT * FROM messages WHERE room_id = ?", (room_id,))
```

Named queries show up in the `/admin/metrics` slow-query dashboard. Anonymous queries are invisible.

### Read/Write Executor Split
Reads and writes use **separate thread pool executors** to prevent write contention from stalling reads:
- `_read_executor` — for SELECT queries
- `_write_executor` — for INSERT/UPDATE/DELETE/DDL

Don't mix them. If you're adding a new DB operation, pick the right executor.

### ContextVar Propagation
When dispatching to thread executors, context vars (e.g., request-scoped query buffers) must be propagated explicitly. See `db.py` for the pattern using `contextvars.copy_context().run(...)`.

---

## 🏗️ Architecture Notes

- **App entry:** `src/deadrop/app.py` — FastAPI app, route registration, lifespan
- **DB layer:** `src/deadrop/db.py` — all SQL, migrations, `InstrumentedConnection` usage
- **Metrics:** `src/deadrop/metrics.py` — StatsD + in-memory, `InstrumentedConnection`, slow query tracking
- **Auth:** `src/deadrop/auth.py` — namespace/secret derivation, hashing
- **Rooms:** `src/deadrop/rooms.py` — room creation, subscription, pub/sub fanout

### Attachment Caching
Attachments are cached client-side in a `Map` keyed by attachment ID. **Never re-fetch an attachment the client has already loaded.** The cache is intentional — don't add server-side cache-busting logic without understanding the client contract.

### Schema Migrations
Schema version is tracked in `SCHEMA_VERSION` in `db.py`. Increment it and add a migration function when changing the schema. Migrations run at startup via `init_db()`. Test migrations against both fresh DBs and existing DBs with data.

---

## 🎨 Code Style

- **No speculation.** Measure before concluding. Use `InstrumentedConnection` slow logs, not guesses.
- **No "prior behavior" comments.** Comments describe what the code IS, not what it WAS.
- **Explicit column names in SQL.** Never rely on positional ordering in INSERT/SELECT.
- **Named queries everywhere.** Every `conn.execute()` call must have a query name as the first argument.
- **Type annotations on new public functions.**

---

## 🚀 Deploy

```bash
git push dokku main
```

The app auto-restarts via Procfile. Health check: `GET /health`.

Wait for the deploy to finish before pushing again. Check logs if health check is slow:

```bash
ssh dokku@h1.dokku.heare.io logs deaddrop -t
```

---

## ⚠️ Common Gotchas

- The package name is `deadrop` (one 'd') — the project is called `deaddrop`. Historical, intentional.
- Turso writes are ~154ms vs ~1ms for SQLite — expected in production, not a bug.
- The dedup window is 60 seconds — identical messages from the same sender within that window are silently dropped.
- Message TTL defaults to 24 hours after read. Don't assume messages persist indefinitely.
- Rooms use pub/sub fanout — a write to a room immediately fans out to all subscribers via SSE.

---

## 📋 PR Checklist

- [ ] `uv run ruff check . && uv run ruff format --check .` passes
- [ ] `uv run pytest tests/ -q --timeout=30` passes
- [ ] Client-side changes tested in browser
- [ ] New DB queries use `InstrumentedConnection` with named queries
- [ ] No "prior behavior" comments added
- [ ] CI green after push
