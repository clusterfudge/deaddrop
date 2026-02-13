"""CLI for deadrop administration.

Manages configuration in ~/.config/deadrop/:
- config.yaml: Global config (URL, bearer token)
- namespaces/{ns_hash}.yaml: Per-namespace config with mailbox credentials

Also supports local .deaddrop directories for offline/testing use:
- .deaddrop/config.yaml: Local namespace registry
- .deaddrop/data.db: SQLite database

The CLI is for administrators to manage namespaces and mailboxes.
Mailbox owners receive their credentials from the admin and use the API directly.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import cyclopts
import httpx

from .config import (
    GlobalConfig,
    NamespaceConfig,
    Source,
    get_config_dir,
    init_wizard,
)
from .discovery import find_deaddrop_dir

app = cyclopts.App(
    name="deadrop",
    help="Minimal inbox-only messaging for agents",
)

ns_app = cyclopts.App(name="ns", help="Namespace management")
identity_app = cyclopts.App(name="identity", help="Identity (mailbox) management")
message_app = cyclopts.App(name="message", help="Message operations (for testing)")
jobs_app = cyclopts.App(name="jobs", help="Scheduled job operations")
archive_app = cyclopts.App(name="archive", help="Archive and rehydration operations")
invite_app = cyclopts.App(name="invite", help="Invite management for web users")
source_app = cyclopts.App(name="source", help="Multi-source configuration management")

app.command(ns_app)
app.command(identity_app)
app.command(message_app)
app.command(jobs_app)
app.command(archive_app)
app.command(invite_app)
app.command(source_app)


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


# --- Claim Helpers (needed early for top-level command) ---


def _claim_local_invite(invite_url: str, key_override: str | None = None):
    """Claim a local file:// invite URL."""
    import base64
    from urllib.parse import parse_qs, unquote, urlparse

    from .crypto import decrypt_invite_secret

    parsed = urlparse(invite_url)
    query_params = parse_qs(parsed.query)
    fragment = parsed.fragment

    # Extract path from file:// URL
    deaddrop_path = Path(unquote(parsed.path))

    # Extract invite code
    invite_code = query_params.get("invite", [None])[0]
    if not invite_code:
        print("Error: Invalid local invite URL format", file=sys.stderr)
        print("Expected: file:///path/to/.deaddrop?invite=<code>#<key>", file=sys.stderr)
        sys.exit(1)

    # Get key from fragment, override, or prompt
    key_base64 = key_override or fragment
    if not key_base64:
        print("The invite URL appears to be missing the key fragment (after #).")
        print("This can happen if the URL wasn't quoted in the shell.")
        print()
        key_base64 = input("Paste the full invite URL again, or just the key: ").strip()
        # If they pasted the full URL, extract the fragment
        if key_base64.startswith("file://") and "#" in key_base64:
            key_base64 = key_base64.split("#", 1)[1]

    if not key_base64:
        print("Error: No key provided", file=sys.stderr)
        sys.exit(1)

    # Decode the invite code: ns:identity_id:encrypted_secret:invite_id
    try:
        assert invite_code is not None
        invite_data = base64.urlsafe_b64decode(invite_code).decode()
        ns, identity_id, encrypted_secret, invite_id = invite_data.split(":")
    except Exception:
        print("Error: Invalid invite code", file=sys.stderr)
        sys.exit(1)

    if not deaddrop_path.exists():
        print(f"Error: Local deaddrop not found at {deaddrop_path}", file=sys.stderr)
        sys.exit(1)

    # Decrypt the secret
    try:
        mailbox_secret = decrypt_invite_secret(
            encrypted_secret_hex=encrypted_secret,
            key_base64=key_base64,
            invite_id=invite_id,
        )
    except Exception as e:
        print(f"Error: Failed to decrypt credentials: {e}", file=sys.stderr)
        sys.exit(1)

    print("Claiming local invite...")
    print(f"  Path: {deaddrop_path}")
    print(f"  Namespace: {ns}")
    print(f"  Identity: {identity_id}")

    # Save to local config with local_path in namespace metadata
    ns_cfg = NamespaceConfig.load(ns)
    if ns_cfg is None:
        ns_cfg = NamespaceConfig(
            ns=ns,
            secret="",  # We don't have namespace-level access
            metadata={"local_path": str(deaddrop_path)},
            created_at=datetime.now(timezone.utc).isoformat(),
        )

    # Add the mailbox
    ns_cfg.add_mailbox(
        id=identity_id,
        secret=mailbox_secret,
    )
    ns_cfg.save()

    print()
    print("✓ Local invite claimed successfully!")
    print(f"  Credentials saved to: {ns_cfg.get_path()}")
    print()
    print("You can now use the CLI to interact with this mailbox:")
    print(f"  deadrop message inbox {ns}")


def _claim_remote_invite(invite_url: str, key_override: str | None = None):
    """Claim a remote HTTP/HTTPS invite URL."""
    import re
    from urllib.parse import urlparse

    from .crypto import decrypt_invite_secret

    cfg = get_config()

    # Parse the invite URL
    if invite_url.startswith("http://") or invite_url.startswith("https://"):
        parsed = urlparse(invite_url)
        path = parsed.path
        fragment = parsed.fragment
        server_url = f"{parsed.scheme}://{parsed.netloc}"
    elif invite_url.startswith("/"):
        # Just a path like /join/abc123#key
        if "#" in invite_url:
            path, fragment = invite_url.split("#", 1)
        else:
            path = invite_url
            fragment = ""
        server_url = cfg.url
    else:
        print("Error: Invalid invite URL format", file=sys.stderr)
        print("Expected: https://server/join/{id}#key", file=sys.stderr)
        sys.exit(1)

    # Extract invite_id from path
    match = re.match(r"/join/([a-f0-9]+)", path)
    if not match:
        print("Error: Could not parse invite ID from URL", file=sys.stderr)
        sys.exit(1)

    assert match is not None  # for type checker - we exit above if None
    invite_id = match.group(1)

    # Get key from fragment, override, or prompt
    key_base64 = key_override or fragment
    if not key_base64:
        print("The invite URL appears to be missing the key fragment (after #).")
        print("This can happen if the URL wasn't quoted in the shell.")
        print()
        key_base64 = input("Paste the full invite URL again, or just the key: ").strip()
        # If they pasted the full URL, extract the fragment
        if "#" in key_base64:
            key_base64 = key_base64.split("#", 1)[1]

    if not key_base64:
        print("Error: No key provided", file=sys.stderr)
        sys.exit(1)

    print(f"Claiming invite from {server_url}...")

    # Get invite info first
    info_response = httpx.get(f"{server_url}/api/invites/{invite_id}/info", timeout=30.0)
    if info_response.status_code == 404:
        print("Error: Invite not found", file=sys.stderr)
        sys.exit(1)
    elif info_response.status_code == 410:
        print("Error: Invite has already been claimed or expired", file=sys.stderr)
        sys.exit(1)
    elif info_response.status_code >= 400:
        print(f"Error: {info_response.text}", file=sys.stderr)
        sys.exit(1)

    info = info_response.json()
    print(f"  Namespace: {info.get('namespace_display_name') or info['ns']}")
    print(f"  Identity: {info.get('identity_display_name') or info['identity_id']}")

    # Claim the invite
    claim_response = httpx.post(f"{server_url}/api/invites/{invite_id}/claim", timeout=30.0)
    if claim_response.status_code == 410:
        print("Error: Invite has already been claimed or expired", file=sys.stderr)
        sys.exit(1)
    elif claim_response.status_code >= 400:
        print(f"Error: {claim_response.text}", file=sys.stderr)
        sys.exit(1)

    claim_data = claim_response.json()

    # Decrypt the secret
    try:
        mailbox_secret = decrypt_invite_secret(
            encrypted_secret_hex=claim_data["encrypted_secret"],
            key_base64=key_base64,
            invite_id=invite_id,
        )
    except Exception as e:
        print(f"Error: Failed to decrypt credentials: {e}", file=sys.stderr)
        sys.exit(1)

    # Save to local config
    ns = claim_data["ns"]
    identity_id = claim_data["identity_id"]

    ns_cfg = NamespaceConfig.load(ns)
    if ns_cfg is None:
        ns_cfg = NamespaceConfig(
            ns=ns,
            secret="",
            display_name=claim_data.get("namespace_display_name"),
            created_at=datetime.now(timezone.utc).isoformat(),
        )

    ns_cfg.add_mailbox(
        id=identity_id,
        secret=mailbox_secret,
        display_name=claim_data.get("identity_display_name") or claim_data.get("display_name"),
    )
    ns_cfg.save()

    print()
    print("✓ Invite claimed successfully!")
    print(f"  Credentials saved to: {ns_cfg.get_path()}")
    print()
    print("You can now use the CLI to interact with this mailbox:")
    print(f"  deadrop message inbox {ns}")
    print(f'  deadrop message send {ns} <recipient_id> "Hello!"')


def _do_claim(invite_url: str):
    """Claim an invite URL (dispatches to local or remote handler)."""
    if invite_url.startswith("file://"):
        _claim_local_invite(invite_url)
    else:
        _claim_remote_invite(invite_url)


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


@app.command
def claim(invite_url: str):
    """Claim an invite link and save credentials locally.

    Examples:
        deadrop claim 'https://deaddrop.example.com/join/abc123#key'
        deadrop claim 'file:///path/to/.deaddrop?invite=code#key'

    Tip: Quote the URL to preserve the # fragment in your shell.
    If the fragment is stripped, you'll be prompted to re-enter it.
    """
    _do_claim(invite_url)


@app.command
def listen(
    ns: str,
    *,
    identity_id: str | None = None,
    inbox: bool = False,
    rooms: bool = False,
    all: bool = True,
    json_output: bool = False,
    timeout: int = 30,
):
    """Listen for new messages across inbox and rooms.

    Subscribes to topic changes and prints events as they arrive.
    Press Ctrl+C to stop.

    Args:
        ns: Namespace ID or slug
        identity_id: Identity to listen as (uses first if not specified)
        inbox: Subscribe to inbox only
        rooms: Subscribe to rooms only
        all: Subscribe to both inbox and rooms (default)
        json_output: Output events as JSON lines
        timeout: Poll timeout in seconds (1-60)
    """
    import json

    config = get_namespace_config(ns)
    ns_id = config.ns

    # Get identity
    if identity_id:
        if identity_id not in config.mailboxes:
            raise cyclopts.ValidationError(f"Identity {identity_id} not found in namespace")
        identity = config.mailboxes[identity_id]
        identity_id = identity_id
    else:
        if not config.mailboxes:
            raise cyclopts.ValidationError("No identities in namespace")
        identity_id = list(config.mailboxes.keys())[0]
        identity = config.mailboxes[identity_id]

    # Determine what to subscribe to
    if inbox and not rooms:
        subscribe_inbox = True
        subscribe_rooms = False
    elif rooms and not inbox:
        subscribe_inbox = False
        subscribe_rooms = True
    else:
        subscribe_inbox = True
        subscribe_rooms = True

    # Build topics
    global_config = get_config()
    topics = {}

    if subscribe_inbox:
        topics[f"inbox:{identity_id}"] = None

    if subscribe_rooms:
        # Fetch rooms via API
        try:
            url = f"{global_config.url}/{ns_id}/rooms"
            resp = httpx.get(
                url,
                headers={"X-Inbox-Secret": identity.secret},
                timeout=30.0,
            )
            if resp.status_code == 200:
                room_list = resp.json()
                for room in room_list:
                    topics[f"room:{room['room_id']}"] = None
        except Exception as e:
            print(f"Warning: Failed to list rooms: {e}", file=sys.stderr)

    if not topics:
        print("No topics to subscribe to.", file=sys.stderr)
        sys.exit(1)

    topic_names = ", ".join(topics.keys())
    if not json_output:
        print(f"Subscribing to: {topic_names}")
        print("Waiting for events... (Ctrl+C to stop)")
        print()

    # Subscribe loop
    try:
        while True:
            try:
                url = f"{global_config.url}/{ns_id}/subscribe"
                resp = httpx.post(
                    url,
                    headers={"X-Inbox-Secret": identity.secret},
                    json={"topics": topics, "mode": "poll", "timeout": timeout},
                    timeout=timeout + 10,
                )

                if resp.status_code != 200:
                    print(f"Error {resp.status_code}: {resp.text}", file=sys.stderr)
                    import time

                    time.sleep(5)
                    continue

                data = resp.json()
                events = data.get("events", {})

                if not events:
                    continue  # Timeout, loop again

                for topic, mid in events.items():
                    # Update cursor
                    topics[topic] = mid

                    if json_output:
                        print(json.dumps({"topic": topic, "latest_mid": mid}))
                    else:
                        # Fetch and display the actual message
                        _display_event(global_config.url, ns_id, identity.secret, topic, mid)

            except httpx.TimeoutException:
                continue  # Normal timeout, loop again
            except httpx.ConnectError as e:
                print(f"Connection error: {e}", file=sys.stderr)
                import time

                time.sleep(5)
    except KeyboardInterrupt:
        if not json_output:
            print("\nStopped.")


def _display_event(base_url: str, ns: str, secret: str, topic: str, mid: str):
    """Fetch and display a subscription event."""
    topic_type, topic_id = topic.split(":", 1)

    if topic_type == "inbox":
        try:
            resp = httpx.get(
                f"{base_url}/{ns}/inbox/{topic_id}",
                headers={"X-Inbox-Secret": secret},
                params={"after": mid},
                timeout=10.0,
            )
            if resp.status_code == 200:
                messages = resp.json().get("messages", [])
                if messages:
                    for msg in messages:
                        from_id = msg.get("from", "unknown")[:8]
                        body = msg.get("body", "")
                        print(f"[inbox] {from_id}: {body}")
                else:
                    print(f"[inbox] New activity (mid: {mid[:12]}...)")
            else:
                print(f"[inbox] New activity (mid: {mid[:12]}...)")
        except Exception:
            print(f"[inbox] New activity (mid: {mid[:12]}...)")

    elif topic_type == "room":
        try:
            resp = httpx.get(
                f"{base_url}/{ns}/rooms/{topic_id}/messages",
                headers={"X-Inbox-Secret": secret},
                params={"after": mid, "limit": "10"},
                timeout=10.0,
            )
            if resp.status_code == 200:
                messages = resp.json().get("messages", [])
                if messages:
                    for msg in messages:
                        from_id = msg.get("from_id", "unknown")[:8]
                        body = msg.get("body", "")
                        print(f"[room:{topic_id[:8]}] {from_id}: {body}")
                else:
                    print(f"[room:{topic_id[:8]}] New activity (mid: {mid[:12]}...)")
            else:
                print(f"[room:{topic_id[:8]}] New activity (mid: {mid[:12]}...)")
        except Exception:
            print(f"[room:{topic_id[:8]}] New activity (mid: {mid[:12]}...)")


# --- Namespace Commands ---


@ns_app.command
def ns_create(
    display_name: str | None = None,
    metadata_json: str | None = None,
    ttl_hours: int = 24,
    *,
    local: bool = False,
    path: str | None = None,
):
    """Create a new namespace.

    Creates the namespace on the server (or locally with --local) and saves credentials.

    --ttl-hours: TTL in hours for messages after they are read (default: 24)
    --local: Create a local namespace in .deaddrop directory
    --path: Path for local .deaddrop directory (default: git root or cwd)
    """
    metadata = {}
    if display_name:
        metadata["display_name"] = display_name
    if metadata_json:
        metadata.update(json.loads(metadata_json))

    if local or path:
        # Create local namespace
        from .client import Deaddrop

        if path:
            deaddrop_path = Path(path)
        else:
            # Auto-discover or create
            existing = find_deaddrop_dir()
            if existing:
                deaddrop_path = existing
            else:
                from .discovery import get_deaddrop_init_path

                deaddrop_path = get_deaddrop_init_path()

        # Create or open local deaddrop
        if deaddrop_path.exists():
            client = Deaddrop.local(path=deaddrop_path)
        else:
            client = Deaddrop.create_local(path=deaddrop_path)

        ns = client.create_namespace(
            display_name=display_name,
            ttl_hours=ttl_hours,
            metadata=metadata if metadata else None,
        )
        client.close()

        # Save namespace config with local_path so we can find it later
        ns_config = NamespaceConfig(
            ns=ns["ns"],
            secret=ns["secret"],
            display_name=display_name,
            metadata={"local_path": str(deaddrop_path.absolute())},
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        ns_config.save()

        print("Local namespace created!")
        print(f"  ID: {ns['ns']}")
        print(f"  Location: {deaddrop_path}")
        print(f"  Config saved to: {ns_config.get_path()}")
        if ns.get("slug"):
            print(f"  Slug: {ns['slug']}")
        return

    # Remote namespace (existing behavior)
    cfg = get_config()

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
def ns_list(*, remote: bool = False, local: bool = False):
    """List namespaces.

    By default, lists namespaces from ~/.config/deadrop config.
    Use --local to list from .deaddrop directory.
    Use --remote to list from server (requires admin auth).
    """
    # Check for local .deaddrop
    local_deaddrop = find_deaddrop_dir()

    if local:
        # List from local .deaddrop only
        if not local_deaddrop:
            print("No local .deaddrop directory found.")
            print("Create one with: deadrop ns create --local")
            return

        from .client import Deaddrop

        client = Deaddrop.local(path=local_deaddrop)
        namespaces = client.list_namespaces()
        client.close()

        if not namespaces:
            print("No namespaces in local .deaddrop.")
            return

        print(f"Local namespaces (from {local_deaddrop}):")
        for ns in namespaces:
            name = ns.get("metadata", {}).get("display_name", "(unnamed)")
            archived = " [ARCHIVED]" if ns.get("archived_at") else ""
            print(f"  {ns['ns']}  {name}{archived}")
        return

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
            local_marker = " (local)" if NamespaceConfig.load(ns["ns"]) else ""
            print(f"  {ns['ns']}  {name}{archived}{local_marker}")
        return

    # Default: list from ~/.config/deadrop
    namespaces = NamespaceConfig.list_all()
    has_config_ns = bool(namespaces)

    if has_config_ns:
        print("Config namespaces (~/.config/deadrop):")
        for ns_id in namespaces:
            ns_cfg = NamespaceConfig.load(ns_id)
            if ns_cfg:
                name = ns_cfg.display_name or "(unnamed)"
                print(f"  {ns_id}  {name}  ({len(ns_cfg.mailboxes)} mailboxes)")

    # Also show local .deaddrop if it exists
    if local_deaddrop:
        from .client import Deaddrop

        client = Deaddrop.local(path=local_deaddrop)
        local_namespaces = client.list_namespaces()
        client.close()

        if local_namespaces:
            if has_config_ns:
                print()
            print(f"Local namespaces ({local_deaddrop}):")
            for ns in local_namespaces:
                name = ns.get("metadata", {}).get("display_name", "(unnamed)")
                archived = " [ARCHIVED]" if ns.get("archived_at") else ""
                print(f"  {ns['ns']}  {name}{archived}")

    if not has_config_ns and not local_deaddrop:
        print("No namespaces found.")
        print("Use 'deadrop ns create' to create one.")
        print("Use 'deadrop ns create --local' for local/offline use.")


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


@ns_app.command
def set_slug(ns: str, slug: str):
    """Set a human-readable slug for a namespace.

    The slug is used in web app URLs: /app/{slug}
    """
    from . import db

    db.init_db()

    if db.set_namespace_slug(ns, slug):
        print(f"Slug set: {slug}")
        print(f"Web app URL: /app/{slug}")
    else:
        print(
            "Error: Failed to set slug. It may already be taken or namespace not found.",
            file=sys.stderr,
        )
        sys.exit(1)


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


# --- Invite Commands ---


def parse_duration(duration: str) -> int:
    """Parse a duration string like '24h', '1d', '30m' into hours."""
    duration = duration.lower().strip()
    if duration.endswith("h"):
        return int(duration[:-1])
    elif duration.endswith("d"):
        return int(duration[:-1]) * 24
    elif duration.endswith("m"):
        return max(1, int(duration[:-1]) // 60)
    else:
        return int(duration)


def _get_local_namespace_path(ns_cfg: NamespaceConfig) -> Path | None:
    """Get the local .deaddrop path for a namespace, if it's local.

    Returns the path if local, None if remote.
    """
    # Check namespace metadata for local_path
    if ns_cfg.metadata and ns_cfg.metadata.get("local_path"):
        return Path(ns_cfg.metadata["local_path"])

    # Check if any mailbox has local_path metadata (legacy)
    for mb in ns_cfg.mailboxes.values():
        if mb.metadata and mb.metadata.get("local_path"):
            return Path(mb.metadata["local_path"])

    return None


@invite_app.command
def create(
    ns: str,
    identity_id: str,
    *,
    expires_in: str = "24h",
    name: str | None = None,
):
    """Create a shareable invite link for a mailbox.

    The invite allows someone to claim access to the specified identity.
    The link is single-use.

    Automatically detects whether this is a local or remote namespace:
    - Local namespaces: Creates a deadrop:// URL with the path embedded
    - Remote namespaces: Registers the invite on the server

    --expires-in: How long until the invite expires (e.g., '24h', '7d', '1h')
    --name: Optional display name for the invite
    """
    from datetime import timedelta

    from .crypto import create_invite_secrets

    ns_cfg = get_namespace_config(ns)
    cfg = get_config()

    # Verify identity exists locally
    if identity_id not in ns_cfg.mailboxes:
        print(f"Error: Identity {identity_id} not found in local config.", file=sys.stderr)
        sys.exit(1)

    mb = ns_cfg.mailboxes[identity_id]

    # Check if this is a local namespace (has local_path in metadata)
    deaddrop_path = _get_local_namespace_path(ns_cfg)

    # Create the cryptographic secrets
    secrets = create_invite_secrets(mb.secret)

    if deaddrop_path:
        # Create local invite (file:// URL)
        if not deaddrop_path.exists():
            print(f"Error: Local .deaddrop not found at {deaddrop_path}", file=sys.stderr)
            sys.exit(1)

        # Encode ns, id, and encrypted secret into a single invite code
        import base64

        invite_data = f"{ns}:{identity_id}:{secrets.encrypted_secret_hex}:{secrets.invite_id}"
        invite_code = base64.urlsafe_b64encode(invite_data.encode()).decode()

        # file:// URL with fragment for key (consistent with remote format)
        abs_path = str(deaddrop_path.absolute())
        invite_url = f"file://{abs_path}?invite={invite_code}#{secrets.key_base64}"

        print("Local invite created!")
        print(f"  For: {mb.display_name or identity_id}")
        print(f"  Path: {deaddrop_path}")
        print()
        print("Share this link:")
        print(invite_url)
        print()
        print("Claim with:")
        print("  deadrop claim '<url>'")
        print()
        print("Note: Quote the URL to preserve the # fragment in your shell.")

    else:
        # Create remote invite (register on server)
        try:
            hours = parse_duration(expires_in)
        except ValueError:
            print(f"Error: Invalid duration format: {expires_in}", file=sys.stderr)
            sys.exit(1)

        expires_at = (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()

        url = f"{cfg.url}/{ns}/invites"
        headers = {"X-Namespace-Secret": ns_cfg.secret}

        response = httpx.post(
            url,
            headers=headers,
            json={
                "identity_id": identity_id,
                "invite_id": secrets.invite_id,
                "encrypted_secret": secrets.encrypted_secret_hex,
                "display_name": name or mb.display_name,
                "expires_at": expires_at,
            },
            timeout=30.0,
        )

        if response.status_code >= 400:
            print(f"Error {response.status_code}: {response.text}", file=sys.stderr)
            sys.exit(1)

        invite_url = f"{cfg.url}/join/{secrets.invite_id}#{secrets.key_base64}"

        print("Invite created!")
        print(f"  For: {mb.display_name or identity_id}")
        print(f"  Expires: {expires_in}")
        print()
        print("Share this link (single-use):")
        print(invite_url)


@invite_app.command
def list_invites(ns: str, *, include_claimed: bool = False):
    """List pending invites for a namespace.

    --include-claimed: Also show already-claimed invites
    """
    ns_cfg = get_namespace_config(ns)
    cfg = get_config()

    # List invites via API
    url = f"{cfg.url}/{ns}/invites"
    params = {"include_claimed": str(include_claimed).lower()}
    headers = {"X-Namespace-Secret": ns_cfg.secret}

    response = httpx.get(url, headers=headers, params=params, timeout=30.0)

    if response.status_code >= 400:
        print(f"Error {response.status_code}: {response.text}", file=sys.stderr)
        sys.exit(1)

    invites = response.json()

    if not invites:
        print("No invites found.")
        return

    print(f"Invites for namespace {ns}:")
    for inv in invites:
        status = ""
        if inv.get("claimed_at"):
            status = " [CLAIMED]"
        elif inv.get("expires_at"):
            expires = datetime.fromisoformat(inv["expires_at"].replace("Z", "+00:00"))
            if expires < datetime.now(timezone.utc):
                status = " [EXPIRED]"

        name = inv.get("display_name") or inv["identity_id"][:8]
        print(f"  {inv['invite_id'][:12]}...  {name}{status}")


@invite_app.command
def revoke(ns: str, invite_id: str):
    """Revoke (delete) an invite.

    The invite ID can be the full ID or a prefix.
    """
    ns_cfg = get_namespace_config(ns)
    cfg = get_config()

    # List invites to find by prefix
    url = f"{cfg.url}/{ns}/invites"
    headers = {"X-Namespace-Secret": ns_cfg.secret}

    response = httpx.get(url, headers=headers, params={"include_claimed": "true"}, timeout=30.0)

    if response.status_code >= 400:
        print(f"Error {response.status_code}: {response.text}", file=sys.stderr)
        sys.exit(1)

    invites = response.json()
    matches = [i for i in invites if i["invite_id"].startswith(invite_id)]

    if not matches:
        print(f"Error: No invite found matching '{invite_id}'", file=sys.stderr)
        sys.exit(1)

    if len(matches) > 1:
        print(
            f"Error: Multiple invites match '{invite_id}'. Be more specific.",
            file=sys.stderr,
        )
        sys.exit(1)

    full_id = matches[0]["invite_id"]

    # Revoke via API
    response = httpx.delete(f"{cfg.url}/{ns}/invites/{full_id}", headers=headers, timeout=30.0)

    if response.status_code >= 400:
        print(f"Error {response.status_code}: {response.text}", file=sys.stderr)
        sys.exit(1)

    print(f"Invite {full_id[:12]}... revoked.")


# --- Source Management Commands ---


@source_app.command
def source_list():
    """List configured sources.

    Shows all remote servers and local .deaddrop paths that are configured.
    """
    cfg = get_config()

    if not cfg.sources:
        print("No sources configured.")
        print()
        print("Add a remote source:")
        print("  deadrop source add myserver --remote https://deaddrop.example.com")
        print()
        print("Add a local source:")
        print("  deadrop source add local-dev --local /path/to/.deaddrop")
        return

    print("Configured sources:")
    for source in cfg.sources:
        default_marker = " (default)" if source.name == cfg.default_source else ""
        if source.type == "remote":
            print(f"  {source.name}: remote @ {source.url}{default_marker}")
        else:
            print(f"  {source.name}: local @ {source.path}{default_marker}")


@source_app.command
def add(
    name: str,
    *,
    remote: str | None = None,
    local: str | None = None,
    bearer_token: str | None = None,
    set_default: bool = False,
):
    """Add a new source.

    Examples:
        deadrop source add work --remote https://work.deaddrop.io
        deadrop source add local-dev --local /path/to/.deaddrop
        deadrop source add prod --remote https://prod.io --bearer-token xxx --set-default

    --remote: URL for remote server
    --local: Path to local .deaddrop directory
    --bearer-token: Bearer token for admin auth (remote only)
    --set-default: Make this the default source
    """
    if remote and local:
        print("Error: Specify either --remote or --local, not both.", file=sys.stderr)
        sys.exit(1)

    if not remote and not local:
        print("Error: Must specify --remote <url> or --local <path>.", file=sys.stderr)
        sys.exit(1)

    cfg = get_config()

    if remote:
        source = Source(
            name=name,
            type="remote",
            url=remote,
            bearer_token=bearer_token,
        )
    else:
        # Validate local path exists
        assert local is not None  # we checked above that either remote or local is set
        local_path = Path(local)
        if not local_path.exists():
            print(f"Warning: Path does not exist yet: {local}", file=sys.stderr)
        source = Source(
            name=name,
            type="local",
            path=str(local_path.absolute()),
        )

    cfg.add_source(source)

    if set_default:
        cfg.default_source = name

    cfg.save()

    print(f"Source '{name}' added.")
    if set_default:
        print("Set as default source.")


@source_app.command
def remove(name: str):
    """Remove a source by name."""
    cfg = get_config()

    if not cfg.remove_source(name):
        print(f"Error: Source '{name}' not found.", file=sys.stderr)
        sys.exit(1)

    cfg.save()
    print(f"Source '{name}' removed.")


@source_app.command
def default(name: str | None = None):
    """Set or show the default source.

    Without arguments, shows the current default.
    With a name argument, sets that source as default.
    """
    cfg = get_config()

    if name is None:
        if cfg.default_source:
            source = cfg.get_source(cfg.default_source)
            if source:
                loc = source.url if source.type == "remote" else source.path
                print(f"Default source: {cfg.default_source} ({source.type} @ {loc})")
            else:
                print(f"Default source: {cfg.default_source} (not found in sources)")
        else:
            print("No default source set.")
            print("Set one with: deadrop source default <name>")
        return

    if not cfg.get_source(name):
        print(f"Error: Source '{name}' not found.", file=sys.stderr)
        print("Add it first with: deadrop source add", file=sys.stderr)
        sys.exit(1)

    cfg.default_source = name
    cfg.save()
    print(f"Default source set to '{name}'.")


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


# ============================================================================
# Room commands
# ============================================================================

room_app = cyclopts.App(name="room", help="Room (group chat) operations")
app.command(room_app)


@room_app.command(name="send")
def room_send(
    ns: str,
    room_id: str,
    body: str,
    *,
    identity_id: str | None = None,
):
    """Send a message to a room.

    Args:
        ns: Namespace ID or slug
        room_id: Room ID
        body: Message body
        identity_id: Identity to send as (uses first if not specified)
    """
    config = get_namespace_config(ns)
    ns_id = config.ns  # Resolve slug to ID

    # Get identity
    if identity_id:
        if identity_id not in config.mailboxes:
            raise cyclopts.ValidationError(f"Identity {identity_id} not found in namespace")
        identity = config.mailboxes[identity_id]
    else:
        if not config.mailboxes:
            raise cyclopts.ValidationError("No identities in namespace")
        identity_id = list(config.mailboxes.keys())[0]
        identity = config.mailboxes[identity_id]

    # Send message via direct httpx request (needs X-Inbox-Secret)
    global_config = get_config()
    url = f"{global_config.url}/{ns_id}/rooms/{room_id}/messages"

    resp = httpx.post(
        url,
        json={"body": body, "content_type": "text/plain"},
        headers={"X-Inbox-Secret": identity.secret},
        timeout=30.0,
    )

    if resp.status_code >= 400:
        print(f"Error {resp.status_code}: {resp.text}", file=sys.stderr)
        sys.exit(1)

    data = resp.json()
    print(f"Message sent: {data.get('mid', 'unknown')}")


@room_app.command(name="messages")
def room_messages(
    ns: str,
    room_id: str,
    *,
    identity_id: str | None = None,
    limit: int = 20,
):
    """Read messages from a room.

    Args:
        ns: Namespace ID or slug
        room_id: Room ID
        identity_id: Identity to read as (uses first if not specified)
        limit: Max messages to show
    """
    config = get_namespace_config(ns)
    ns_id = config.ns

    # Get identity
    if identity_id:
        if identity_id not in config.mailboxes:
            raise cyclopts.ValidationError(f"Identity {identity_id} not found in namespace")
        identity = config.mailboxes[identity_id]
    else:
        if not config.mailboxes:
            raise cyclopts.ValidationError("No identities in namespace")
        identity_id = list(config.mailboxes.keys())[0]
        identity = config.mailboxes[identity_id]

    # Get messages via direct httpx request
    global_config = get_config()
    url = f"{global_config.url}/{ns_id}/rooms/{room_id}/messages?limit={limit}"

    resp = httpx.get(
        url,
        headers={"X-Inbox-Secret": identity.secret},
        timeout=30.0,
    )

    if resp.status_code >= 400:
        print(f"Error {resp.status_code}: {resp.text}", file=sys.stderr)
        sys.exit(1)

    data = resp.json()
    messages = data.get("messages", [])
    if not messages:
        print("No messages in room")
        return

    for msg in messages:
        from_id = msg.get("from_id", "unknown")[:8]
        body = msg.get("body", "")
        created = msg.get("created_at", "")[:19]
        print(f"[{created}] {from_id}: {body}")
