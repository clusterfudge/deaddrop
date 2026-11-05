# e2e_rotation: real clients through a secret rotation

An end-to-end harness for versioned identity secrets (`deadrop rekey`, #127). Four
identities in one throwaway namespace and room, each held by a **real client**, ride two
rotations:

1. **grace**: `rekey identity` + `rekey all` with an overlap window (old secret works
   until the new one is first used, then it is burned);
2. **revoke-now**: `rekey all --revoke-now` (old secrets die immediately).

After each, every client must recover by the route it actually has, and the room history
must be intact. The harness never prints a secret, works in a fresh 0700 directory per run,
leak-scans every log it and the server wrote, and then deletes everything except the
redacted `results.json` and `logs/harness.log`.

It is **not** part of the unit-test job: nothing here matches `test_*.py`, it lives outside
`tests/`, and `pr-checks.yml` runs `pytest -m "not integration"` over `tests/`. It needs
headless Chromium, a harness1 tools checkout and a few minutes of wall time; run it by hand.

---

## What each client class proves

| client | real code | how it recovers | proves |
|---|---|---|---|
| `pyclient` | `deadrop.client.Deaddrop`, bundle re-read from the credential store on each start | `rekey` PATCHes the store; next start just works | the `--credential-store` fix-forward route |
| `h1-tools` | harness1 `comms/deaddrop_send_room.py` + `deaddrop_read_room.py`, unmodified | every call re-reads the store | the same route through the scripts the twin actually runs |
| `h1-watcher` | harness1 `feeds/deaddrop_watcher.py` main loop, unmodified | logs a 403 after the burn, then re-reads the store and keeps delivering (tools #120); older tools go dark until restarted, which also passes and is reported as `dark until restart` | that a long-lived reader never keeps reading on a burned secret, which recovery route it took, and that a restart also recovers |
| `mcp` | `mcp` streamable-HTTP client + `ClientSession` against `/mcp/{ns}/{secret}` | recovery invite claimed with the PIN; new URL | the invite route for a client with the secret in its URL; the old URL gets an opaque 401 |
| `browser` | headless Chromium on the real `join.html` + `app.html` | opens the delivered recovery invite, types the PIN | the invite + PIN flow end to end in the web app |
| `browser-stale` | headless Chromium with `localStorage` left on the old secret | sees 403 `credential_retired` + the "ask for a recovery invite" alert; re-onboarded with `rekey invite` | what a forgotten tab experiences |

The harness1 scripts are copied unmodified from a `fritz-heare/tools` checkout into the run's
work dir (`--h1-tools`). The one change is made in-process by `clients/h1_run.py`: requests to
the real credential-store ports (`:9876`/`:9877`) are rewritten to the throwaway store, so the
real store is never contacted.

## The checks (60 with push enabled)

| group | checks | what |
|---|---|---|
| setup | 1 | push subscription registered for the browser identity |
| healthy | 6 | watcher up; every client posts + reads; the watcher sees another client's message |
| dry-run | 3 | `rekey all --dry-run` plans 4, routes 2 to the store and 2 to invites, changes nothing |
| rotation | 3 | both rekeys succeed; store PATCHed for both store-driven identities; invites delivered 0600 via `--deliver-cmd` |
| overlap | 5 | every v1 still accepted before its successor is used; the watcher still receiving |
| grace | 15 | each client recovers by its route; each burned v1 gets 403 `credential_retired`; watcher 403 then store re-read (or dark), and back after restart; stale tab alert + fresh invite; `deadrop claim` refuses a recovery invite (no PIN input: a finding); MCP v2 == claimed secret, old URL 401 |
| grace final | 6 | all five clients post + read; history intact |
| grace push | 3 | subscription survives rotation; old secret cannot list it; `/push/test` targets it |
| revoke-now | 9 | `--revoke-now` succeeds; all four v2 rejected immediately; MCP v2 URL dark; watcher as in grace; browser alert |
| revoke-now final | 5 | four clients post + read; history intact |
| revoke-now push | 3 | as for grace |
| status | 1 | `rekey status` flags burned versions with stale use |

Without VAPID on the target the six push checks and the setup check are skipped (53).

---

## Run it locally (throwaway sqlite)

```bash
uv sync --group dev
.venv/bin/playwright install chromium       # once
nice -n 19 .venv/bin/python scripts/e2e_rotation/fleet_e2e.py --local --h1-tools ~/src/fritz-tools
```

`--local` migrates a fresh sqlite file in the work dir, starts `uvicorn deadrop.api:app` on a
free loopback port with a random admin token and freshly generated VAPID keys, and stops it
before the leak scan. Wall time is about two and a half minutes.

Run it **niced and one at a time**: it holds one uvicorn, one Chromium, a watcher and
short-lived client processes. Between phases it waits while `sensors` reports the CPU package
above `$DDFLEET_MAX_TEMP` (default 85 C); on a machine without `sensors` it does not wait.

Expected tail:

```
... 60/60 checks passed
... leak scan: 0 hits over N files (server logs: server.log) for M minted values
... leak scan positive control (credstore.json + CLI ns config): K hits
... work dir cleaned; kept /tmp/dd-rotation-e2e-XXXX/results.json and .../logs/harness.log
RESULTS: /tmp/dd-rotation-e2e-XXXX/results.json  OK
```

Exit status is 0 only if every check passed, the scan found **zero** minted values in the
logs and results, its positive control (the two files that hold secrets by design: the
throwaway credential store and the CLI namespace config) found **more than zero**, and, for
`--local`, the server log was among the files scanned. `--keep-work` keeps the whole work dir
(secrets included, 0700) for debugging; delete it yourself.

Against an already-running loopback test server instead:

```bash
STAGING_URL=http://127.0.0.1:<port> DEADROP_ADMIN_TOKEN=<that server's made-up token> \
  nice -n 19 .venv/bin/python scripts/e2e_rotation/fleet_e2e.py --h1-tools ~/src/fritz-tools
```

The target must be loopback and not a credential-store port; anything else is refused.
Put the server's log in the run's `logs/` (or use `turso_stage.py`) if you want it scanned.

---

## Run it against a Turso rehearsal clone

`turso_stage.py` starts two staging servers on loopback against a clone of production made by
`scripts/rehearse_on_turso_clone.py`, runs the harness against one, then measures how fast a
burn on one process is seen by the other.

```bash
export REHEARSAL_DB=deaddrop-rehearsal-$(date +%Y%m%d)
nice -n 19 .venv/bin/python scripts/rehearse_on_turso_clone.py create
nice -n 19 .venv/bin/python scripts/e2e_rotation/turso_stage.py --h1-tools ~/src/fritz-tools both
```

- **Clone-only guard.** The clone env comes from `rehearse_on_turso_clone._clone_env()`: it
  refuses any name that is not `deaddrop-rehearsal-*` or is the source, checks the hostname
  belongs to the clone, and mints a one-day token for the clone only. The script also refuses
  to start unless `REHEARSAL_DB` has that prefix. Only the platform token is read from the
  credential store (`turso` entry), in process, never printed.
- **Admin token.** A random value made up at startup and given only to the two staging
  processes. There is no real admin token anywhere in the run.
- **Teardown is automatic.** On every way out (normal exit, exception, Ctrl-C, SIGTERM, a
  server that ignores SIGTERM for 15 s) the servers are stopped, then the clone is destroyed
  through `rehearse_on_turso_clone.py`'s guarded teardown. `--keep-clone` skips it; then run
  `rehearse_on_turso_clone.py teardown` yourself. Run any other rehearsal phases first.
- **Leak scan.** The harness scans the staging logs for every value it minted or received;
  after the servers stop, the stager scans them again for the clone token, the admin token,
  the VAPID private key and the propagation secrets, with a made-up canary as its positive
  control. A missing staging log fails the run.

Namespaces the rehearsal harnesses create carry `metadata.rehearsal`, and
`rehearse_on_turso_clone.py verify` skips their identities in the legacy-id check (their ids
are random by design).
