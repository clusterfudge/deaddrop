"""Apply pending schema migrations and exit: ``python -m deadrop.migrate``.

This is the Procfile ``release`` task. Dokku runs it in a one-off container of
the new image after the build and before any new web container starts; a
nonzero exit aborts the deploy and the running container keeps serving.
Migrations skip versions already recorded in ``schema_version``, so a re-run
applies nothing. Output names the backend host and versions, never the token.
"""

from __future__ import annotations

import os
import sys
import time

from . import db


def main() -> int:
    if db.is_using_libsql():
        target = f"turso {db._turso_hostname()}"
    else:
        target = f"sqlite {os.environ.get('DEADROP_DB', ':memory:')}"
    started = time.monotonic()
    try:
        before = db.get_schema_version()
        applied = db.init_db()
        after = db.get_schema_version()
    except Exception as e:
        print(f"deadrop migrate: FAILED on {target}: {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    finally:
        db.close_db()
    print(
        f"deadrop migrate: {target} v{before} -> v{after},"
        f" applied {applied or 'nothing'} in {time.monotonic() - started:.1f}s",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
