# Bad-cursor hot loop — working notes

*Worktree: `~/src/deaddrop-cursor-hotloop`, branch `fix/bad-cursor-hot-loop`, off `origin/main` (`3ade179`).
Commit: `abc9b60`.*

Every claim below is tagged **[measured]** (I ran it / read it) or **[inferred]**
(reasoning over measurements). Nothing here is tagged from the incident brief
alone unless I re-verified it.

---

## § 1. The defect, re-verified at source

| Location | What it does |
|---|---|
| `static/js/api.js:320-325` @ `origin/main` | `if (!this.cursors[topic] \|\| mid > this.cursors[topic])` — JS string compare |
| `static/js/api.js:297-304` @ `origin/main` | `_loadCursors` `JSON.parse`s localStorage with no validation |
| `api.py:170-187` | `_coerce_read_cursor` returns `None` for a non-v7 cursor |
| `api.py:2366-2371` @ `origin/main` | applies that `None` to every topic |
| `events.py:193-195` | `last_seen is None` → "caller has never seen this topic — any message is new" |
| `static/js/api.js:468-493`, bound at `:477` | `_runPollLoop` re-polls on receipt, bounded only by 3 min |

**[measured]** `grep -rn "isUuidV7\|substr(\|charAt(14)" src/deadrop/static/js/` returns
nothing in `api.js` pre-fix — the v7 check genuinely existed nowhere on the client.
Only `db.py:3452` (`substr(last_read_mid, 15, 1) != '7'`) and `db.py:3508`
(`last_read_mid[14] != "7"`) had it.

**[measured]** The archaeology holds. `0655541` (2026-05-03, "lenient v4-cursor handling
on read paths (strict on write)"), `8525314` ("non-v7 read cursors must not block v7
advancement"), `7362fc4` ("replace broken 'pending-' optimistic mid") are all present
and all ancestors of `origin/main`. `8525314`'s message names the exact wedged cursor:
`1e141d46-f442-4391-b714-98aeb44c442f`. **None of them are touched by this PR.**

---

## § 2. The live datum that settles the scoping argument

**[measured]** In the surviving log window, at `2026-07-31T13:38:29Z`:

```
ignoring non-v7 read cursor for cursor for room:0698e39d-5b8b-76f4-8000-87645fce0630:
'1e141d46-f442-4391-b714-98aeb44c442f'
```

The same poisoned v4, **still being presented by a live client 30 minutes after the
reboot**, from a client running JS we cannot update until it reloads. One occurrence in
a minute that saw 18 subscribes.

**[inferred]** This is why the server fix is the primary one: the client fix repairs a
profile on next page load, and a hot-looping tab is by definition a tab that is not
reloading.

---

## § 3. What changed

### Server — `api.py:2399-2407`

```python
event_bus = get_event_bus()
coerced: dict[str, str | None] = {}
for topic_key, cursor in request.topics.items():
    resolved = _coerce_read_cursor(cursor, f"cursor for {topic_key}")
    if resolved is None and cursor:
        resolved = event_bus.get_latest(ns, topic_key)
    coerced[topic_key] = resolved
request.topics = coerced
```

Chose **"resolve to current latest at the subscribe boundary"** over a sentinel
threaded into `_check_changes`, and over "block regardless":

- No new type, no new state, no change to `_check_changes` semantics. `resolved is
  None and cursor` is the whole distinction — absent/empty cursor is falsy and keeps
  its existing meaning.
- "Block regardless" would starve a poisoned client of notifications entirely. Pinning
  to latest still lets a publish inside the window wake the subscription, which hands
  the client a v7 mid it can recover its cursor from.

### Server — `events.py:290-309`

`get_latest` now consults `_db_fallback` (and caches, exactly as `_check_changes`
does) when the process has seen no publish for a topic.

**[inferred, then tested]** Without this the fix does not survive a restart: a fresh
container has an empty `_latest`, `get_latest` returns `None`, and the poisoned cursor
resolves right back to "never seen". The burst began ~2 minutes after a container
replacement, so this is the case that matters, not an edge case. Covered by
`test_invalid_cursor_pins_to_db_latest_on_a_cold_bus`.

### Logging — `api.py:170-199`, `api.py:249-289`

`bad_cursor` now goes to the `deadrop.access` structlog logger. The timing middleware
computes `endpoint` / `client` / `user_agent` / `identity_id` **before** `call_next`
and binds them as contextvars, so handler-side logs inherit the same attribution the
access log has. Access-log output is unchanged (the fields now arrive via contextvars
instead of explicit kwargs).

**[measured]** Actual emitted line from the test run:

```
[warning] bad_cursor  client=testclient cursor=1e141d46-f442-4391-b714-98aeb44c442f
          endpoint=subscribe field='cursor for room:06a6ca6f-...' identity_id=e62eee87a0cd4246
          request_id=702b7f19796a user_agent=testclient
```

No rate limiting added. Per-request emission is what made the burst countable (811
lines, and the count per minute is how the 3-minute bound was established). ~4.5
lines/s is not a logging problem.

### Client — `static/js/api.js:16-19`, `:313-333`, `:349-357`

(`isUuidV7` at `api.js:16`, `_loadCursors` at `:313`, `updateCursor` at `:350`.)
`isUuidV7` uses the same pattern as the server's `_UUID7_RE` (`api.py:154-156`) so the
client never retains a cursor the server would discard. `updateCursor` treats a non-v7
stored cursor as unset and ignores a non-v7 incoming mid (no re-poisoning);
`_loadCursors` drops non-v7 entries.

### Not done

- **No 400 on read paths.** Strictness alone re-creates the forever-wedge `0655541`
  fixed. Left to Sean.
- **No metrics counter** for bad cursors. The reported gap was "no client context in
  the log"; a counter is a separate, speculative addition.
- **No rate limiting** (see above).

---

## § 4. § 6 — why SSE does not spin, and why the poll path did

**The answer is state ownership.** `stream` (`events.py:236-284`) keeps its own cursor
copy and advances it locally:

- `events.py:265` — `cursors = dict(topics)` — a private copy at stream open.
- `events.py:282-283` — `for topic, info in changes.items(): cursors[topic] = info["latest_mid"]` — every
  yield advances the server-side cursor.

**[inferred, high confidence]** So a `None` cursor in SSE mode yields **exactly once**
per topic and then blocks on `condition.wait()` (`events.py:279`) forever after. The
poisoned client's localStorage is irrelevant to the stream's own progress — the ABC
docstring's contract ("first yields any immediately-available changes, then waits",
`events.py:84-85`) is honored because the cursor lives in the generator, not in the
client.

`subscribe` (`events.py:202-234`) is stateless. It gets the client's cursor on every
call and has no memory between calls, so a cursor that can never advance produces an
immediate return on every call, forever. `_runPollLoop` (`api.js:468-493`) re-polls on
receipt, so "immediate return" becomes "request rate".

**That is the model the poll path should follow, and this PR is the stateless version
of it:** the server supplies the cursor the client cannot (its current latest) instead
of accepting "unknown" as "nothing".

Latent bug in SSE? **[inferred]** No, for `None`. One caveat **[measured]**: if a
stream's first `_check_changes` finds nothing (empty topic) and a later `publish`
arrives, the cursor advances normally — the ordering invariants at `events.py:245-262`
are about lost notifications, not about cursor validity. Nothing in `stream` compares a
client-supplied cursor more than once.

### Why SSE failed for that client

**Not determinable from available data.** [measured] The pre-reboot container's logs
are gone (CID `30985f1dca0` → `345f6c9448d`); the surviving window starts at
13:06:09Z, after the reboot, and the SSE failure would have been logged — if at all —
in the client's console, which we do not collect. There is no server-side record of an
SSE stream terminating abnormally.

**[measured]** The SSE path does share the DB connection pool with everything else:
`api.py:2379` `_require_active_namespace(ns)` runs the `is_namespace_archived` query
before the stream branch at `api.py:2409`, and `event_bus.stream`'s cold-start
`_db_fallback` (`events.py:176-186` via `db.get_topic_latest`) also goes through the
shared read executor (`db.py:241-272`). So a connection-layer stall *could* kill an SSE
connection and push the client into `_runPollLoop`. **That is a mechanism, not a
finding** — see § 5.

---

## § 5. § 7 — do the load event and the latency event connect?

**No, and my instrument for connecting them turns out to be nearly useless here.**

**[measured]** `slow_request`'s threshold is `SLOW_REQUEST_THRESHOLD_MS`, default
**500ms** — `api.py:309`, applied at `api.py:335`.

Two measurements kill the connection:

1. **[measured]** The hot-loop requests were ~96ms p50, i.e. **below the threshold by
   5x**. They could not have been counted as slow requests. The flat count is exactly
   what the hot loop predicts, so it is not evidence against the hot loop — but it is
   also not evidence that the hot loop caused any latency.

2. **[measured]** `slow_request` is dominated by long-polls *by design*. Of 435
   `slow_request` events in the 36-minute window, **337 are `endpoint=subscribe`**, and
   the maximum `duration_ms` observed anywhere is **31769.4ms** — a 30s subscribe
   timeout plus overhead. A metric whose population is 77% intentional 30-second
   blocking cannot detect a latency event.

**[measured]** Per-minute `slow_request` counts across the whole surviving window are
flat: 9, 10, 14, 12 (burst minutes 13:07–13:10) then 11, 10, 11, 11, **21**, 14, 10, 8,
7, 13, 14, 9, 14, 13, 18, 11, 15, 9, 9, 19, 18, 11, 15, 9, 19, 10, 9, 11, 9, 13, 14.
The peak (21, at 13:15) is **after** the burst self-terminated.

**Verdict:** this PR fixes a real, measured, self-inflicted **load amplifier**. It does
**not** explain the latency that prompted the reboot, and I cannot claim it prevents a
recurrence of that. The burst ended on its own 3-minute bound, not because of the
reboot.

**What would refute my answer:** a `slow_request` line during 13:08–13:10 with
`endpoint=subscribe` and `duration_ms` in the 100ms–2s range (i.e. hot-loop requests
that *were* slow), or a pre-reboot log showing subscribe volume correlating with rising
`db_total_ms`. Neither exists in surviving data.

---

## § 6. The Hrana / #49 hypothesis — tested, not supported (in this window)

**[measured]** Zero occurrences across the entire life of the current container
(13:06:09Z → 13:42:20Z, 3766 log lines) of:

| Signal | Count |
|---|---|
| `Replaced stuck DB executors` (`db.py:355`) | **0** |
| `cascading pool exhaustion` (`db.py:365`, fires when a replace follows within 60s) | **0** |
| `stream not found` / `hrana` | **0** |
| `health_ping` failures | **0** |
| `ignoring non-v7 read cursor` | **811** |

**[measured]** Unauthenticated DB-latency canary (`_require_active_namespace` runs
before auth, `api.py:2379`): 4/4 probes `401` in 0.2247 / 0.2210 / 0.2188 / 0.2185s at
13:50:57Z, container up ~45 min. Tight, no variance. The 13:00 incident's
`is_namespace_archived` at 344ms would have shown here.

**[measured] `/debug/db` cannot be read: `DEADROP_ADMIN_TOKEN` is not set in the
container.** `ssh dokku@h1.dokku.heare.io enter deaddrop web.1 env` returns 74 vars;
`grep -c '^DEADROP_ADMIN_TOKEN=' → 0` (`TURSO_AUTH_TOKEN` *is* present, so app config
is visible — the admin token genuinely isn't configured). Setting it requires
`dokku config:set`, which restarts the app; out of scope. **This is the single highest-value
follow-up: the cumulative counters (`hrana_stream_errors_total`,
`executor_replace_count_total`) are the only artifact that survives the event.** No
token was printed at any point.

**[measured] PR #50 was closed, not merged.** `gh pr view 50` → `state: CLOSED`,
`mergedAt: null`, `mergeCommit: null`. Its commit `a1cd16a` ("debounce executor replace
+ throttle health checks", message references `#49`) is **not an ancestor of
`origin/main`** — `git branch -a --contains a1cd16a` returns only
`fix/runtime-hangs-executor-pool`. What *is* on main is `48f43fb` (PR #76, issue #51),
whose own comment at `db.py:154-160` says **"Pure instrumentation: counters +
timestamps... they change no control flow."**

**[inferred]** So the #49 *diagnostics* shipped and the #49 *fix* did not. There is no
debounce on `_replace_db_executor` (`db.py:318-372` increments counters and replaces
unconditionally) and no health-check throttle in `get_connection`. If #49 recurs, the
unmerged `a1cd16a` is a ready patch. **Note the numbering: the brief said "PR #50 …
issue #49"; #49 does not resolve as a PR (`gh pr view 49` → not found), and the PR is
#50. I did not re-derive which issue number is authoritative.**

**Not supported ≠ refuted.** The predicted recurrence window is 30–60 minutes from
process start; at 45 minutes the canary is clean, so the upper edge (~14:05–14:10Z)
is untested. Absence of `Replaced stuck DB executors` is real evidence (the log fires
on the event, and the log survived), but only for *this* container. The pre-reboot
container's window is unrecoverable.

**Conclusion: the pre-reboot latency remains unexplained.** Hrana stream expiry is the
leading candidate on mechanism, and its own instrumentation says it has not fired since
the reboot.

---

## § 7. Observability gap worth closing

An unauthenticated namespace-scoped latency canary would have alarmed during the
pre-reboot window and needs no credentials:

```
curl -s -o /dev/null -w '%{http_code} %{time_total}s' \
  https://deaddrop.dokku.heare.io/<ns>/rooms      # 401, but the DB was already touched
```

Caveat: `time_total` bundles TLS and network RTT, so it is a canary, not a DB timer.
The precise instrument is `/debug/db`, which needs `DEADROP_ADMIN_TOKEN` set.

Second gap: `slow_request` at a 500ms threshold cannot see past intentional 30-second
long-polls. Either exclude `endpoint=subscribe` or compare against `db_total_ms`
instead of `duration_ms`.
