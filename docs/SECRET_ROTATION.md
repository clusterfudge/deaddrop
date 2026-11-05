# Secret rotation, burns and recovery

An identity's id is minted once and never changes. Its secrets are
**versions** in `identity_secrets` (`active`, `grace`, `burned`); rooms,
history, push subscriptions, the recovery email and the PIN all attach to the
id. Identities created before this existed were seeded with version 1 and
keep their `sha256(secret)[:16]` ids.

## Auth lookup table

Every server process loads `sha256(secret) -> (identity, version, status)`
into memory at startup and authenticates from it with no database read.
Writes in the same process update it immediately. Other processes follow the
`auth_generation` counter, read every `DEADROP_AUTH_REFRESH_SECONDS`
(default 5): **a burn made in one process is honoured by the others within
one interval plus a generation read and a table reload.** A hash the table
does not hold triggers at most one generation check per
`DEADROP_AUTH_MISS_REFRESH_SECONDS` (default 1), so a new identity created
in another process is found at once and a flood of random secrets costs one
small read per second.

## Runbook

Run on a trusted host that holds the namespace config. Nothing prints a
secret or a PIN.

```bash
deadrop rekey all <ns> --dry-run --credential-map agents.json   # ids and counts only
deadrop rekey identity <ns> <id> [--grace 600 | --revoke-now] [--set-pin] --deliver-cmd '<sender>'
deadrop rekey all <ns> --credential-map agents.json --deliver-cmd '<sender>'
deadrop rekey status <ns>                      # versions, stale use, PIN, invite claims
deadrop rekey invite <ns> <id> --deliver-cmd '<sender>'   # fresh recovery invite
deadrop rekey burn <ns> <id> <version>         # burn one version by hand
deadrop rekey rollback <ns> <id> <version> --yes
deadrop rekey recovery <ns> <id> [--email ADDR] [--clear-email] [--set-pin]
deadrop rekey unlock <ns> <id>                 # clear a PIN lockout
```

`rekey` mints version N+1. Older versions keep working until N+1 first
authenticates; then they are burned (or move to `grace` for `--grace`
seconds). `--revoke-now` burns them at mint time. Only a request that hashes
to N+1 can trigger the switch, so an old or burned secret can neither cause
nor block it.

`agents.json` maps identity ids to credential-store entries:
`{"<id>": {"credential": "deaddrop.fritz", "field": "secret"}}`; those get
the new secret PATCHed into the store. Everyone else gets a **recovery
invite**: single use, at most 15 minutes, needs the identity's PIN, and
minting one revokes the identity's earlier unclaimed ones. The URL is written
to `~/.config/deadrop/recovery/<id>-<invite>.url` (0600) and, with
`--deliver-cmd`, piped to that command's stdin with `DEADROP_INVITE_IDENTITY`,
`DEADROP_INVITE_EXPIRES` and (if set) `DEADROP_INVITE_TO` = the identity's
recovery email.

Five wrong PINs lock recovery claims for the identity until
`rekey unlock`. A wrong PIN does not consume the invite.

A device still holding a burned secret gets 403 with detail
`credential_retired: ...`; the web client shows "ask for a recovery invite",
and `rekey status` marks the version `STALE-USE` with its attempt count.
