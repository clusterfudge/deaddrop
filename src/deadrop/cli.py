"""CLI for deadrop administration.

Manages configuration in ~/.config/deadrop/:
- config.yaml: Global config (URL, bearer token)
- namespaces/{ns_hash}.yaml: Per-namespace config with mailbox credentials

The CLI is for administrators to manage namespaces and mailboxes.
Mailbox owners receive their credentials from the admin and use the API directly.
"""

import json
import os
import sys
from datetime import datetime, timezone

import cyclopts
import httpx

from .config import (
    GlobalConfig,
    NamespaceConfig,
    get_config_dir,
    init_wizard,
)

app = cyclopts.App(
    name="deadrop",
    help="Minimal inbox-only messaging for agents",
)

ns_app = cyclopts.App(name="ns", help="Namespace management")
identity_app = cyclopts.App(name="identity", help="Identity (mailbox) management")
message_app = cyclopts.App(name="message", help="Message operations (for testing)")
jobs_app = cyclopts.App(name="jobs", help="Scheduled job operations")
archive_app = cyclopts.App(name="archive", help="Archive and rehydration operations")

app.command(ns_app)
app.command(identity_app)
app.command(message_app)
app.command(jobs_app)
app.command(archive_app)


def get_config() -> GlobalConfig:
    """Get global config, running wizard if needed."""
    if not GlobalConfig.exists():
        print("No configuration found. Let's set one up.\n")
        return init_wizard()
    return GlobalConfig.load()


def get_namespace_config(ns: str) -> NamespaceConfig:
    """Get namespace config or exit with error."""
    config = NamespaceConfig.load(ns)
    if config is None:
        print(f"Error: Namespace {ns} not found in local config.", file=sys.stderr)
        print("Run 'deadrop ns list' to see available namespaces.", file=sys.stderr)
        raise SystemExit(1)
    return config


def api_request(
    method: str,
    path: str,
    *,
    config: GlobalConfig | None = None,
    ns_config: NamespaceConfig | None = None,
    json_data: dict | None = None,
) -> httpx.Response:
    """Make an API request."""
    if config is None:
        config = get_config()

    url = f"{config.url}{path}"
    headers = {}

    # Add bearer token for admin endpoints
    if config.bearer_token and path.startswith("/admin"):
        headers["Authorization"] = f"Bearer {config.bearer_token}"

    # Add namespace secret if provided
    if ns_config:
        headers["X-Namespace-Secret"] = ns_config.secret

    response = httpx.request(method, url, headers=headers, json=json_data, timeout=30.0)

    if response.status_code >= 400:
        print(f"Error {response.status_code}: {response.text}", file=sys.stderr)
        sys.exit(1)

    return response


def print_json(data):
    """Pretty print JSON data."""
    print(json.dumps(data, indent=2, default=str))


# --- Init Command ---


@app.command
def init():
    """Initialize deadrop configuration.

    Runs an interactive wizard to set up:
    - Server URL
    - Bearer token for admin operations
    """
    if GlobalConfig.exists():
        confirm = input("Configuration already exists. Overwrite? [y/N] ")
        if confirm.lower() != "y":
            print("Cancelled.")
            return

    init_wizard()


@app.command
def config():
    """Show current configuration."""
    cfg = get_config()
    print(f"Config directory: {get_config_dir()}")
    print(f"Server URL: {cfg.url}")
    print(f"Bearer token: {'(set)' if cfg.bearer_token else '(not set)'}")

    namespaces = NamespaceConfig.list_all()
    print(f"\nLocal namespaces: {len(namespaces)}")
    for ns in namespaces:
        ns_cfg = NamespaceConfig.load(ns)
        if ns_cfg:
            name = ns_cfg.display_name or "(unnamed)"
            print(f"  {ns}: {name} ({len(ns_cfg.mailboxes)} mailboxes)")


# --- Namespace Commands ---


@ns_app.command
def ns_create(
    display_name: str | None = None,
    metadata_json: str | None = None,
    ttl_hours: int = 24,
):
    """Create a new namespace.

    Creates the namespace on the server and saves credentials locally.

    --ttl-hours: TTL in hours for messages after they are read (default: 24)
    """
    cfg = get_config()

    metadata = {}
    if display_name:
        metadata["display_name"] = display_name
    if metadata_json:
        metadata.update(json.loads(metadata_json))

    json_data = {"ttl_hours": ttl_hours}
    if metadata:
        json_data["metadata"] = metadata

    response = api_request(
        "POST",
        "/admin/namespaces",
        config=cfg,
        json_data=json_data,
    )

    data = response.json()

    # Save namespace config locally
    ns_config = NamespaceConfig(
        ns=data["ns"],
        secret=data["secret"],
        display_name=display_name,
        metadata=metadata,
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    ns_config.save()

    print("Namespace created!")
    print(f"  ID: {data['ns']}")
    print(f"  Config saved to: {ns_config.get_path()}")


@ns_app.command
def ns_list(*, remote: bool = False):
    """List namespaces.

    By default, lists namespaces from local config.
    Use --remote to list from server (requires admin auth).
    """
    if remote:
        cfg = get_config()
        response = api_request("GET", "/admin/namespaces", config=cfg)
        namespaces = response.json()

        if not namespaces:
            print("No namespaces found on server.")
            return

        print("Remote namespaces:")
        for ns in namespaces:
            name = ns.get("metadata", {}).get("display_name", "(unnamed)")
            archived = " [ARCHIVED]" if ns.get("archived_at") else ""
            local = " (local)" if NamespaceConfig.load(ns["ns"]) else ""
            print(f"  {ns['ns']}  {name}{archived}{local}")
    else:
        namespaces = NamespaceConfig.list_all()

        if not namespaces:
            print("No namespaces in local config.")
            print("Use 'deadrop ns create' to create one.")
            return

        print("Local namespaces:")
        for ns_id in namespaces:
            ns_cfg = NamespaceConfig.load(ns_id)
            if ns_cfg:
                name = ns_cfg.display_name or "(unnamed)"
                print(f"  {ns_id}  {name}  ({len(ns_cfg.mailboxes)} mailboxes)")


@ns_app.command
def ns_show(ns: str):
    """Show namespace details from local config."""
    ns_cfg = get_namespace_config(ns)

    print(f"Namespace: {ns_cfg.ns}")
    print(f"Display name: {ns_cfg.display_name or '(none)'}")
    print(f"Created: {ns_cfg.created_at or 'unknown'}")
    print(f"Config file: {ns_cfg.get_path()}")
    print(f"\nMailboxes ({len(ns_cfg.mailboxes)}):")

    for id, mb in ns_cfg.mailboxes.items():
        name = mb.display_name or "(unnamed)"
        print(f"  {id}  {name}")


@ns_app.command
def ns_delete(ns: str, *, force: bool = False, remote: bool = False):
    """Delete a namespace.

    By default, only removes local config.
    Use --remote to also delete from server (hard delete).
    """
    ns_cfg = NamespaceConfig.load(ns)

    if remote:
        if not force:
            confirm = input(f"Delete namespace {ns} from SERVER and ALL its data? [y/N] ")
            if confirm.lower() != "y":
                print("Cancelled.")
                return

        cfg = get_config()
        api_request("DELETE", f"/admin/namespaces/{ns}", config=cfg)
        print(f"Namespace {ns} deleted from server.")

    if ns_cfg:
        if not remote and not force:
            confirm = input(f"Remove local config for namespace {ns}? [y/N] ")
            if confirm.lower() != "y":
                print("Cancelled.")
                return

        ns_cfg.delete()
        print("Local config removed.")
    elif not remote:
        print(f"Namespace {ns} not found in local config.")


@ns_app.command
def archive(ns: str):
    """Archive a namespace (soft delete, rejects future writes)."""
    ns_cfg = get_namespace_config(ns)
    cfg = get_config()

    # Use namespace secret for this operation
    url = f"{cfg.url}/{ns}/archive"
    headers = {"X-Namespace-Secret": ns_cfg.secret}

    response = httpx.post(url, headers=headers, timeout=30.0)

    if response.status_code >= 400:
        print(f"Error {response.status_code}: {response.text}", file=sys.stderr)
        sys.exit(1)

    print(f"Namespace {ns} archived.")


@ns_app.command
def secret(ns: str):
    """Show the namespace secret (for advanced use)."""
    ns_cfg = get_namespace_config(ns)
    print(f"Namespace: {ns_cfg.ns}")
    print(f"Secret: {ns_cfg.secret}")
    print("\nThis secret allows full control over mailboxes in this namespace.")
    print("Keep it secure!")


# --- Identity (Mailbox) Commands ---


@identity_app.command
def identity_create(
    ns: str,
    display_name: str | None = None,
    metadata_json: str | None = None,
):
    """Create a new identity (mailbox) in a namespace.

    Creates the mailbox on the server and saves credentials to namespace config.
    """
    ns_cfg = get_namespace_config(ns)
    cfg = get_config()

    metadata = {}
    if display_name:
        metadata["display_name"] = display_name
    if metadata_json:
        metadata.update(json.loads(metadata_json))

    # Create on server
    url = f"{cfg.url}/{ns}/identities"
    headers = {"X-Namespace-Secret": ns_cfg.secret}

    response = httpx.post(
        url,
        headers=headers,
        json={"metadata": metadata} if metadata else None,
        timeout=30.0,
    )

    if response.status_code >= 400:
        print(f"Error {response.status_code}: {response.text}", file=sys.stderr)
        sys.exit(1)

    data = response.json()

    # Save to local config
    ns_cfg.add_mailbox(
        id=data["id"],
        secret=data["secret"],
        display_name=display_name,
        metadata=metadata,
    )
    ns_cfg.save()

    print("Identity created!")
    print(f"  ID: {data['id']}")
    print(f"  Namespace: {ns}")
    print("\nCredentials saved to namespace config.")
    print(f"Use 'deadrop identity export {ns} {data['id']}' to get credentials for handoff.")


@identity_app.command
def identity_list(ns: str, *, remote: bool = False):
    """List identities in a namespace.

    By default, lists from local config.
    Use --remote to list from server.
    """
    ns_cfg = get_namespace_config(ns)
    cfg = get_config()

    if remote:
        url = f"{cfg.url}/{ns}/identities"
        headers = {"X-Namespace-Secret": ns_cfg.secret}

        response = httpx.get(url, headers=headers, timeout=30.0)

        if response.status_code >= 400:
            print(f"Error {response.status_code}: {response.text}", file=sys.stderr)
            sys.exit(1)

        identities = response.json()

        if not identities:
            print("No identities found on server.")
            return

        print(f"Remote identities in namespace {ns}:")
        for identity in identities:
            name = identity.get("metadata", {}).get("display_name", "(unnamed)")
            local = " (local)" if identity["id"] in ns_cfg.mailboxes else ""
            print(f"  {identity['id']}  {name}{local}")
    else:
        if not ns_cfg.mailboxes:
            print(f"No identities in local config for namespace {ns}.")
            print("Use 'deadrop identity create' to create one.")
            return

        print(f"Local identities in namespace {ns}:")
        for id, mb in ns_cfg.mailboxes.items():
            name = mb.display_name or "(unnamed)"
            print(f"  {id}  {name}")


@identity_app.command
def identity_show(ns: str, identity_id: str):
    """Show identity details from local config."""
    ns_cfg = get_namespace_config(ns)

    if identity_id not in ns_cfg.mailboxes:
        print(f"Error: Identity {identity_id} not found in local config.", file=sys.stderr)
        sys.exit(1)

    mb = ns_cfg.mailboxes[identity_id]

    print(f"Identity: {mb.id}")
    print(f"Namespace: {ns}")
    print(f"Display name: {mb.display_name or '(none)'}")
    print(f"Created: {mb.created_at or 'unknown'}")
    if mb.metadata:
        print(f"Metadata: {json.dumps(mb.metadata)}")


@identity_app.command
def identity_export(ns: str, identity_id: str, *, format: str = "text"):
    """Export identity credentials for handoff to mailbox owner.

    Formats: text, json, env
    """
    ns_cfg = get_namespace_config(ns)
    cfg = get_config()

    if identity_id not in ns_cfg.mailboxes:
        print(f"Error: Identity {identity_id} not found in local config.", file=sys.stderr)
        sys.exit(1)

    mb = ns_cfg.mailboxes[identity_id]

    if format == "json":
        print(
            json.dumps(
                {
                    "url": cfg.url,
                    "namespace": ns,
                    "id": mb.id,
                    "secret": mb.secret,
                    "display_name": mb.display_name,
                },
                indent=2,
            )
        )
    elif format == "env":
        print(f"DEADROP_URL={cfg.url}")
        print(f"DEADROP_NAMESPACE={ns}")
        print(f"DEADROP_INBOX_ID={mb.id}")
        print(f"DEADROP_INBOX_SECRET={mb.secret}")
    else:  # text
        print(f"Mailbox credentials for '{mb.display_name or identity_id}'")
        print("=" * 50)
        print(f"Server URL: {cfg.url}")
        print(f"Namespace:  {ns}")
        print(f"ID:         {mb.id}")
        print(f"Secret:     {mb.secret}")
        print("=" * 50)
        print("\nThe mailbox owner uses these credentials to:")
        print(f"  - Send messages: POST /{ns}/send")
        print(f"  - Read inbox:    GET /{ns}/inbox/{mb.id}")
        print(f"  - List peers:    GET /{ns}/identities")


@identity_app.command
def identity_delete(ns: str, identity_id: str, *, force: bool = False, remote: bool = False):
    """Delete an identity.

    By default, only removes from local config.
    Use --remote to also delete from server.
    """
    ns_cfg = get_namespace_config(ns)
    cfg = get_config()

    if remote:
        if not force:
            confirm = input(
                f"Delete identity {identity_id} from SERVER and all its messages? [y/N] "
            )
            if confirm.lower() != "y":
                print("Cancelled.")
                return

        url = f"{cfg.url}/{ns}/identities/{identity_id}"
        headers = {"X-Namespace-Secret": ns_cfg.secret}

        response = httpx.delete(url, headers=headers, timeout=30.0)

        if response.status_code >= 400:
            print(f"Error {response.status_code}: {response.text}", file=sys.stderr)
            sys.exit(1)

        print(f"Identity {identity_id} deleted from server.")

    if identity_id in ns_cfg.mailboxes:
        if not remote and not force:
            confirm = input(f"Remove identity {identity_id} from local config? [y/N] ")
            if confirm.lower() != "y":
                print("Cancelled.")
                return

        ns_cfg.remove_mailbox(identity_id)
        ns_cfg.save()
        print("Identity removed from local config.")
    elif not remote:
        print(f"Identity {identity_id} not found in local config.")


# --- Message Commands (for testing) ---


@message_app.command
def send(
    ns: str,
    to: str,
    body: str,
    *,
    identity_id: str | None = None,
    ttl: int | None = None,
):
    """Send a message to another identity.

    Uses the first mailbox in the namespace config, or specify --identity-id.
    Primarily for testing - mailbox owners typically use the API directly.
    """
    ns_cfg = get_namespace_config(ns)
    cfg = get_config()

    # Find the sender identity
    if identity_id:
        if identity_id not in ns_cfg.mailboxes:
            print(f"Error: Identity {identity_id} not found in local config.", file=sys.stderr)
            sys.exit(1)
        sender = ns_cfg.mailboxes[identity_id]
    else:
        if not ns_cfg.mailboxes:
            print("Error: No mailboxes in namespace config.", file=sys.stderr)
            print("Create one with 'deadrop identity create'", file=sys.stderr)
            sys.exit(1)
        # Use first mailbox
        sender = next(iter(ns_cfg.mailboxes.values()))
        print(f"Sending as: {sender.display_name or sender.id}")

    # Send message
    url = f"{cfg.url}/{ns}/send"
    headers = {"X-Inbox-Secret": sender.secret}
    json_data = {"to": to, "body": body}
    if ttl is not None:
        json_data["ttl"] = ttl

    response = httpx.post(url, headers=headers, json=json_data, timeout=30.0)

    if response.status_code >= 400:
        print(f"Error {response.status_code}: {response.text}", file=sys.stderr)
        sys.exit(1)

    data = response.json()
    print(f"Message sent: {data['mid']}")


@message_app.command
def inbox(
    ns: str,
    identity_id: str | None = None,
    *,
    unread: bool = False,
    after: str | None = None,
    json_output: bool = False,
):
    """Read messages from an inbox.

    Uses the first mailbox in the namespace config, or specify identity-id.
    Reading marks messages as read and starts the TTL countdown.

    --unread: Only show unread messages
    --after: Only show messages after this message ID (cursor for pagination)
    """
    ns_cfg = get_namespace_config(ns)
    cfg = get_config()

    # Find the identity
    if identity_id:
        if identity_id not in ns_cfg.mailboxes:
            print(f"Error: Identity {identity_id} not found in local config.", file=sys.stderr)
            sys.exit(1)
        mb = ns_cfg.mailboxes[identity_id]
    else:
        if not ns_cfg.mailboxes:
            print("Error: No mailboxes in namespace config.", file=sys.stderr)
            sys.exit(1)
        mb = next(iter(ns_cfg.mailboxes.values()))
        print(f"Reading inbox for: {mb.display_name or mb.id}\n")

    # Fetch messages
    url = f"{cfg.url}/{ns}/inbox/{mb.id}"
    params = []
    if unread:
        params.append("unread=true")
    if after:
        params.append(f"after={after}")
    if params:
        url += "?" + "&".join(params)

    headers = {"X-Inbox-Secret": mb.secret}
    response = httpx.get(url, headers=headers, timeout=30.0)

    if response.status_code >= 400:
        print(f"Error {response.status_code}: {response.text}", file=sys.stderr)
        sys.exit(1)

    data = response.json()
    messages = data.get("messages", [])

    if json_output:
        print(json.dumps(messages, indent=2, default=str))
        return

    if not messages:
        print("No messages.")
        return

    for msg in messages:
        status = ""
        if msg.get("acked_at"):
            status = " [acked]"
        elif msg.get("read_at"):
            status = " [read]"
        else:
            status = " [unread]"

        # Try to resolve sender name from local config
        from_name = msg["from"]
        if msg["from"] in ns_cfg.mailboxes:
            mb_from = ns_cfg.mailboxes[msg["from"]]
            if mb_from.display_name:
                from_name = f"{mb_from.display_name} ({msg['from'][:8]}...)"

        print(f"--- {msg['mid'][:8]}...{status} ---")
        print(f"From: {from_name}")
        print(f"At:   {msg['created_at']}")
        print(f"\n{msg['body']}\n")


@message_app.command
def message_delete(
    ns: str,
    mid: str,
    identity_id: str | None = None,
):
    """Delete a message immediately.

    Messages are automatically deleted after TTL expires (default 24h after read).
    Use this to delete a message before TTL expires.
    """
    ns_cfg = get_namespace_config(ns)
    cfg = get_config()

    # Find the identity
    if identity_id:
        if identity_id not in ns_cfg.mailboxes:
            print(f"Error: Identity {identity_id} not found in local config.", file=sys.stderr)
            sys.exit(1)
        mb = ns_cfg.mailboxes[identity_id]
    else:
        if not ns_cfg.mailboxes:
            print("Error: No mailboxes in namespace config.", file=sys.stderr)
            sys.exit(1)
        mb = next(iter(ns_cfg.mailboxes.values()))

    url = f"{cfg.url}/{ns}/inbox/{mb.id}/{mid}"
    headers = {"X-Inbox-Secret": mb.secret}
    response = httpx.delete(url, headers=headers, timeout=30.0)

    if response.status_code >= 400:
        print(f"Error {response.status_code}: {response.text}", file=sys.stderr)
        sys.exit(1)

    print(f"Message {mid} deleted.")


# --- Jobs Commands ---


@jobs_app.command
def ttl(
    *,
    archive_path: str | None = None,
    no_delete: bool = False,
    dry_run: bool = False,
):
    """Process expired messages.

    Runs the TTL job locally (requires database access).

    --archive-path: Save expired messages to JSONL files before processing
    --no-delete: Mark as archived but don't delete
    --dry-run: Show what would be processed without making changes
    """
    from . import db, jobs

    db.init_db()

    result = jobs.process_ttl(
        archive_path=archive_path,
        delete=not no_delete,
        dry_run=dry_run,
    )

    if dry_run:
        print(f"Would process {result} expired messages")
    else:
        action = "archived" if no_delete else "deleted"
        print(f"Processed {result} expired messages ({action})")


# --- Archive Commands ---


@archive_app.command
def list_batches(ns: str | None = None):
    """List archive batches.

    Runs locally (requires database access).
    """
    from . import db

    db.init_db()
    batches = db.get_archive_batches(ns)

    if not batches:
        print("No archive batches found.")
        return

    for batch in batches:
        print(
            f"{batch['batch_id']}  ns={batch['ns']}  count={batch['message_count']}  path={batch['archive_path']}"
        )


@archive_app.command
def rehydrate(archive_path: str, *, output: str = "-"):
    """Load messages from an archive file.

    Outputs to stdout by default, or to a file with --output.
    """
    from . import jobs

    messages = jobs.rehydrate_from_local(archive_path)

    if output == "-":
        print_json(messages)
    else:
        with open(output, "w") as f:
            json.dump(messages, f, indent=2, default=str)
        print(f"Wrote {len(messages)} messages to {output}")


@archive_app.command
def archive_export(
    ns: str,
    *,
    participants: str | None = None,
    since: str | None = None,
    include_archived: bool = False,
    output: str = "-",
):
    """Export messages for visualization.

    --participants: Comma-separated list of identity IDs to include
    --since: ISO timestamp, only messages after this time
    --include-archived: Include rehydrated archived messages
    --output: Output file (default: stdout)

    Runs locally (requires database access).
    """
    from . import db, jobs

    db.init_db()

    if participants:
        participant_list = [p.strip() for p in participants.split(",")]
        messages = jobs.export_conversation_view(
            ns=ns,
            participants=participant_list,
            since=since,
            include_archived=include_archived,
        )
    else:
        # Export all messages in namespace
        messages = []
        identities = db.list_identities(ns)
        for identity in identities:
            inbox = db.get_messages(ns, identity["id"], mark_as_read=False)
            messages.extend(inbox)

        # Sort by time
        messages.sort(key=lambda m: m["created_at"])

    if output == "-":
        print_json(messages)
    else:
        with open(output, "w") as f:
            json.dump(messages, f, indent=2, default=str)
        print(f"Exported {len(messages)} messages to {output}", file=sys.stderr)


# --- Server Command ---


@app.command
def serve(
    *,
    host: str = "0.0.0.0",
    port: int = 8000,
    reload: bool = False,
    no_auth: bool = False,
):
    """Run the deadrop server.

    Authentication modes for admin endpoints (creating namespaces):
    - --no-auth: No authentication required (development only!)
    - HEARE_AUTH_URL: Bearer token auth via heare-auth service
    - DEADROP_ADMIN_TOKEN: Legacy static token auth

    Namespace and mailbox operations always require their respective secrets.
    """
    import uvicorn

    from .heare_auth import is_heare_auth_enabled

    if no_auth:
        os.environ["DEADROP_NO_AUTH"] = "1"
        print("WARNING: Running in no-auth mode. Admin endpoints are unprotected!")
        print("         Do not use in production.\n")
    elif not is_heare_auth_enabled() and not os.environ.get("DEADROP_ADMIN_TOKEN"):
        print("Error: No auth method configured.", file=sys.stderr)
        print("Options:", file=sys.stderr)
        print("  --no-auth              Development mode (no auth)", file=sys.stderr)
        print("  HEARE_AUTH_URL=...     heare-auth service URL", file=sys.stderr)
        print("  DEADROP_ADMIN_TOKEN=.. Legacy static token", file=sys.stderr)
        sys.exit(1)

    uvicorn.run(
        "deadrop.api:app",
        host=host,
        port=port,
        reload=reload,
    )


if __name__ == "__main__":
    app()
