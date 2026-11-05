"""Secret rotation ("rekey"), burns and recovery for identities.

An identity's id never changes; its secrets are versions in
``identity_secrets`` (see :mod:`deadrop.db`). Rotation adds a version:

1. **Rekey** (namespace secret): version N+1 is minted ``active``. Older
   versions keep working.
2. **Switch** (automatic): the first request authenticated by version N+1
   moves older live versions to ``grace`` for ``grace_seconds``, or burns
   them at once when it is 0. Only a request hashing to N+1 can do this.
3. ``revoke_now`` burns the older versions at mint time instead.

A burned version is rejected with ``auth.RETIRED_DETAIL`` and its use is
counted (``burned_attempts``, ``last_seen_at``): that is how stale devices
show up in :func:`status`. :func:`burn` and :func:`rollback` set a version's
status by hand.

Recovery: a recovery invite is a single-use invite (TTL capped at
``RECOVERY_INVITE_MAX_SECONDS``) for an identity with a PIN; minting one
revokes the identity's earlier unclaimed recovery invites, and claiming it
needs the PIN. ``PIN_MAX_FAILURES`` wrong PINs lock claiming for the
identity until :func:`unlock_pin`.

Nothing here logs or returns a secret except :func:`rekey_identity`'s
response, which is the only way the new secret leaves the server.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

from .auth import generate_secret, hash_pin, hash_secret, verify_pin

PIN_MAX_FAILURES = 5
RECOVERY_INVITE_MAX_SECONDS = int(os.environ.get("DEADROP_RECOVERY_INVITE_MAX_SECONDS", "900"))


class RekeyError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _db():
    from . import db

    return db


def _identity(c, ns: str, identity_id: str) -> dict:
    db = _db()
    cursor = c.execute(
        """SELECT id, metadata, recovery_email, pin_hash, pin_failures, pin_locked_at
           FROM identities WHERE ns = ? AND id = ?""",
        (ns, identity_id),
        name="rekey.identity",
    )
    row = db._row_to_dict(cursor.description, cursor.fetchone())
    if row is None:
        raise RekeyError(404, "Identity not found")
    return row


def _versions(c, ns: str, identity_id: str) -> list[dict]:
    db = _db()
    cursor = c.execute(
        """SELECT version, status, switch_grace, grace_until, created_at, burned_at,
                  last_seen_at, burned_attempts
           FROM identity_secrets WHERE ns = ? AND identity_id = ? ORDER BY version""",
        (ns, identity_id),
        name="rekey.versions",
    )
    return db._rows_to_dicts(cursor.description, cursor.fetchall())


def _commit(c, ns: str, identity_id: str) -> None:
    db = _db()
    db._bump_auth_generation(c)
    c.commit()
    db.reload_identity_secrets(ns, identity_id)


def _count(c, sql: str, params: tuple, name: str) -> int:
    return int(c.execute(sql, params, name=name).fetchone()[0] or 0)


def plan(ns: str, identity_id: str) -> dict:
    """What a rekey touches. Ids and counts only."""
    c = _db().get_connection()
    _identity(c, ns, identity_id)
    by_status: dict[str, int] = {"active": 0, "grace": 0, "burned": 0}
    for v in _versions(c, ns, identity_id):
        by_status[v["status"]] = by_status.get(v["status"], 0) + 1
    return {
        "versions": by_status,
        "rooms": _count(
            c,
            "SELECT COUNT(*) FROM room_members WHERE ns = ? AND identity_id = ?",
            (ns, identity_id),
            "rekey.plan.rooms",
        ),
        "push_subscriptions": _count(
            c,
            "SELECT COUNT(*) FROM push_subscriptions WHERE ns = ? AND identity_id = ?",
            (ns, identity_id),
            "rekey.plan.push",
        ),
        "unclaimed_invites": _count(
            c,
            "SELECT COUNT(*) FROM invites WHERE ns = ? AND identity_id = ? AND claimed_at IS NULL",
            (ns, identity_id),
            "rekey.plan.invites",
        ),
    }


def rekey_identity(
    ns: str,
    identity_id: str,
    *,
    grace_seconds: int = 0,
    revoke_now: bool = False,
    dry_run: bool = False,
    pin: str | None = None,
) -> dict:
    """Mint version N+1 of ``identity_id``'s secret.

    Returns the new ``version`` and ``secret`` (unless ``dry_run``) and the
    plan counts. ``pin``, if given, replaces the recovery PIN and clears a
    lockout.
    """
    if grace_seconds < 0:
        raise RekeyError(400, "grace_seconds must be >= 0")
    counts = plan(ns, identity_id)
    if dry_run:
        return {"identity_id": identity_id, "dry_run": True, "plan": counts}

    db = _db()
    c = db.get_connection()
    current = _count(
        c,
        "SELECT MAX(version) FROM identity_secrets WHERE ns = ? AND identity_id = ?",
        (ns, identity_id),
        "rekey.max_version",
    )
    version = current + 1
    secret = generate_secret()
    db._insert_secret_version(
        c,
        ns,
        identity_id,
        hash_secret(secret),
        version,
        switch_grace=None if revoke_now else grace_seconds,
    )
    burned: list[int] = []
    if revoke_now:
        burned = [
            v["version"]
            for v in _versions(c, ns, identity_id)
            if v["version"] < version and v["status"] in ("active", "grace")
        ]
        c.execute(
            """UPDATE identity_secrets SET status = 'burned', burned_at = ?
               WHERE ns = ? AND identity_id = ? AND version < ?
               AND status IN ('active', 'grace')""",
            (_now().isoformat(), ns, identity_id, version),
            name="rekey.revoke_now",
        )
    if pin:
        _set_pin(c, ns, identity_id, pin)
    _commit(c, ns, identity_id)
    return {
        "identity_id": identity_id,
        "version": version,
        "secret": secret,
        "burned_versions": burned,
        "plan": counts,
    }


def _set_status(ns: str, identity_id: str, version: int, status: str) -> dict:
    db = _db()
    c = db.get_connection()
    _identity(c, ns, identity_id)
    rows = {v["version"]: v for v in _versions(c, ns, identity_id)}
    if version not in rows:
        raise RekeyError(404, "Secret version not found")
    if rows[version]["status"] == status:
        raise RekeyError(409, f"Version {version} is already {status}")
    if status == "burned":
        c.execute(
            """UPDATE identity_secrets SET status = 'burned', burned_at = ?
               WHERE ns = ? AND identity_id = ? AND version = ?""",
            (_now().isoformat(), ns, identity_id, version),
            name="rekey.burn",
        )
    else:
        c.execute(
            """UPDATE identity_secrets SET status = 'active', burned_at = NULL,
                   grace_until = NULL
               WHERE ns = ? AND identity_id = ? AND version = ?""",
            (ns, identity_id, version),
            name="rekey.rollback",
        )
    _commit(c, ns, identity_id)
    live = sum(1 for v in _versions(c, ns, identity_id) if v["status"] in ("active", "grace"))
    return {"identity_id": identity_id, "version": version, "status": status, "live_versions": live}


def burn(ns: str, identity_id: str, version: int) -> dict:
    """Mark one secret version burned. Takes effect in this process at once."""
    return _set_status(ns, identity_id, version, "burned")


def rollback(ns: str, identity_id: str, version: int) -> dict:
    """Make a version active again. Re-enables a possibly compromised secret."""
    return _set_status(ns, identity_id, version, "active")


def status(ns: str) -> list[dict]:
    """Per identity: versions (no hashes), PIN state, recovery invites."""
    db = _db()
    c = db.get_connection()
    now = _now().isoformat()
    out = []
    for ident in db.list_identities(ns):
        row = _identity(c, ns, ident["id"])
        inv = c.execute(
            """SELECT
                 SUM(CASE WHEN claimed_at IS NULL AND (expires_at IS NULL OR expires_at > ?)
                     THEN 1 ELSE 0 END),
                 SUM(CASE WHEN claimed_at IS NOT NULL THEN 1 ELSE 0 END),
                 MAX(claimed_at)
               FROM invites WHERE ns = ? AND identity_id = ? AND recovery = 1""",
            (now, ns, ident["id"]),
            name="rekey.status.invites",
        ).fetchone()
        out.append(
            {
                "identity_id": ident["id"],
                "display_name": ident["metadata"].get("display_name"),
                "versions": _versions(c, ns, ident["id"]),
                "recovery_email": row["recovery_email"],
                "pin_set": bool(row["pin_hash"]),
                "pin_failures": row["pin_failures"] or 0,
                "pin_locked": bool(row["pin_locked_at"]),
                "recovery_invites": {
                    "live": int(inv[0] or 0) if inv else 0,
                    "claimed": int(inv[1] or 0) if inv else 0,
                    "last_claimed_at": inv[2] if inv else None,
                },
            }
        )
    return out


# --- Recovery email and PIN -------------------------------------------------


def _set_pin(c, ns: str, identity_id: str, pin: str) -> None:
    try:
        pin_hash = hash_pin(pin)
    except ValueError as e:
        raise RekeyError(400, str(e)) from None
    c.execute(
        """UPDATE identities SET pin_hash = ?, pin_failures = 0, pin_locked_at = NULL
           WHERE ns = ? AND id = ?""",
        (pin_hash, ns, identity_id),
        name="rekey.set_pin",
    )


def set_recovery(
    ns: str,
    identity_id: str,
    *,
    recovery_email: str | None = None,
    clear_recovery_email: bool = False,
    pin: str | None = None,
) -> dict:
    """Set the recovery email (default delivery target) and/or the PIN."""
    c = _db().get_connection()
    _identity(c, ns, identity_id)
    if recovery_email is not None or clear_recovery_email:
        c.execute(
            "UPDATE identities SET recovery_email = ? WHERE ns = ? AND id = ?",
            (None if clear_recovery_email else recovery_email, ns, identity_id),
            name="rekey.set_recovery_email",
        )
    if pin:
        _set_pin(c, ns, identity_id, pin)
    c.commit()
    row = _identity(c, ns, identity_id)
    return {
        "identity_id": identity_id,
        "recovery_email": row["recovery_email"],
        "pin_set": bool(row["pin_hash"]),
    }


def unlock_pin(ns: str, identity_id: str) -> dict:
    c = _db().get_connection()
    _identity(c, ns, identity_id)
    c.execute(
        "UPDATE identities SET pin_failures = 0, pin_locked_at = NULL WHERE ns = ? AND id = ?",
        (ns, identity_id),
        name="rekey.unlock_pin",
    )
    c.commit()
    return {"identity_id": identity_id, "pin_locked": False}


def check_recovery_pin(ns: str, identity_id: str, pin: str | None) -> None:
    """Gate a recovery-invite claim on the identity's PIN.

    An attempt is reserved (counter incremented) before the hash is checked,
    so concurrent guesses cannot exceed ``PIN_MAX_FAILURES``; a correct PIN
    resets the counter.
    """
    c = _db().get_connection()
    row = _identity(c, ns, identity_id)
    if not row["pin_hash"]:
        raise RekeyError(409, "No recovery PIN set for this identity")
    if not pin:
        raise RekeyError(401, "pin_required")
    reserved = c.execute(
        """UPDATE identities SET pin_failures = pin_failures + 1
           WHERE ns = ? AND id = ? AND pin_locked_at IS NULL AND pin_failures < ?""",
        (ns, identity_id, PIN_MAX_FAILURES),
        name="rekey.pin_reserve",
    )
    c.commit()
    if reserved.rowcount == 0:
        raise RekeyError(423, "pin_locked: too many wrong PINs; ask the operator to unlock")
    if verify_pin(pin, row["pin_hash"]):
        c.execute(
            "UPDATE identities SET pin_failures = 0 WHERE ns = ? AND id = ?",
            (ns, identity_id),
            name="rekey.pin_ok",
        )
        c.commit()
        return
    c.execute(
        """UPDATE identities SET pin_locked_at = ?
           WHERE ns = ? AND id = ? AND pin_failures >= ? AND pin_locked_at IS NULL""",
        (_now().isoformat(), ns, identity_id, PIN_MAX_FAILURES),
        name="rekey.pin_lock",
    )
    c.commit()
    raise RekeyError(403, "Wrong PIN")


def prepare_recovery_invite(ns: str, identity_id: str, expires_at: str | None) -> str:
    """Validate a recovery invite and revoke the identity's earlier unclaimed ones.

    Returns the expiry to store: the requested one, capped at
    ``RECOVERY_INVITE_MAX_SECONDS`` from now.
    """
    c = _db().get_connection()
    row = _identity(c, ns, identity_id)
    if not row["pin_hash"]:
        raise RekeyError(409, "Set a recovery PIN before minting a recovery invite")
    cap = _now() + timedelta(seconds=RECOVERY_INVITE_MAX_SECONDS)
    expiry = cap
    if expires_at:
        requested = datetime.fromisoformat(expires_at)
        if requested.tzinfo is None:
            requested = requested.replace(tzinfo=timezone.utc)
        expiry = min(requested, cap)
    c.execute(
        """DELETE FROM invites WHERE ns = ? AND identity_id = ? AND recovery = 1
           AND claimed_at IS NULL""",
        (ns, identity_id),
        name="rekey.revoke_previous_recovery_invites",
    )
    c.commit()
    return expiry.isoformat()
