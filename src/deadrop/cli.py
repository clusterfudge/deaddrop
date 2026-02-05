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
room_app = cyclopts.App(name="room", help="Room management and encrypted messaging")
jobs_app = cyclopts.App(name="jobs", help="Scheduled job operations")
archive_app = cyclopts.App(name="archive", help="Archive and rehydration operations")
invite_app = cyclopts.App(name="invite", help="Invite management for web users")
source_app = cyclopts.App(name="source", help="Multi-source configuration management")

app.command(ns_app)
app.command(identity_app)
app.command(message_app)
app.command(room_app)
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


# --- Docs Command ---


@app.command
def docs():
    """Show comprehensive usage documentation.

    Outputs the built-in documentation in Markdown format.
    Covers concepts, authentication, CLI usage, API reference, and encryption.
    """
    import importlib.resources

    # Read the bundled documentation file
    try:
        # Python 3.9+ way
        files = importlib.resources.files("deadrop.docs")
        doc_content = (files / "USAGE.md").read_text()
    except (AttributeError, TypeError):
        # Fallback for older Python
        import importlib.resources as resources

        with resources.open_text("deadrop.docs", "USAGE.md") as f:
            doc_content = f.read()

    print(doc_content)


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
def generate_keys(ns: str, identity_id: str):
    """Generate and register an encryption keypair for an identity.

    Creates a new keypair and registers the public key with the server.
    The private key is stored locally and never sent to the server.

    If the identity already has a keypair, this will rotate the key
    (old key revoked, new key becomes active).
    """
    from deadrop.crypto import generate_keypair

    ns_cfg = get_namespace_config(ns)
    cfg = get_config()

    if identity_id not in ns_cfg.mailboxes:
        print(f"Error: Identity {identity_id} not found in local config.", file=sys.stderr)
        sys.exit(1)

    mb = ns_cfg.mailboxes[identity_id]

    # Generate keypair
    keypair = generate_keypair()

    # Register with server
    url = f"{cfg.url}/{ns}/inbox/{identity_id}/pubkey"
    headers = {"X-Inbox-Secret": mb.secret}
    payload = {
        "public_key": keypair.public_key_base64,
        "signing_public_key": keypair.signing_public_key_base64,
        "algorithm": "nacl-box",
    }

    response = httpx.put(url, headers=headers, json=payload, timeout=30.0)

    if response.status_code >= 400:
        print(f"Error {response.status_code}: {response.text}", file=sys.stderr)
        sys.exit(1)

    result = response.json()

    # Save private key locally
    mb.private_key = keypair.private_key_base64
    mb.pubkey_id = result["pubkey_id"]
    ns_cfg.save()

    print("Keypair generated and registered!")
    print(f"  Public key ID: {result['pubkey_id']}")
    print(f"  Version: {result['version']}")
    print(f"  Algorithm: {result['algorithm']}")
    print("\nPrivate key saved to local config.")
    print("You can now send encrypted messages and sign outgoing messages.")


@identity_app.command
def rotate_key(ns: str, identity_id: str):
    """Rotate the encryption keypair for an identity.

    Generates a new keypair, registers it with the server (revoking the old one),
    and keeps the old private key for decrypting historical messages.

    Alias for generate-keys (same behavior).
    """
    # Just call generate_keys - it handles rotation automatically
    generate_keys(ns, identity_id)


@identity_app.command
def show_pubkey(ns: str, identity_id: str):
    """Show public key information for an identity.

    Shows both local keypair status and server-registered public key.
    """
    from deadrop.crypto import KeyPair, pubkey_id

    ns_cfg = get_namespace_config(ns)
    cfg = get_config()

    if identity_id not in ns_cfg.mailboxes:
        print(f"Error: Identity {identity_id} not found in local config.", file=sys.stderr)
        sys.exit(1)

    mb = ns_cfg.mailboxes[identity_id]

    print(f"Identity: {identity_id}")
    print(f"Display name: {mb.display_name or '(none)'}")
    print()

    # Local keypair status
    print("Local keypair:")
    if mb.private_key:
        keypair = KeyPair.from_private_key_base64(mb.private_key)
        print("  ✓ Private key present")
        print(f"  Public key: {keypair.public_key_base64}")
        print(f"  Signing key: {keypair.signing_public_key_base64}")
        local_pubkey_id = pubkey_id(keypair.public_key)
        print(f"  Pubkey ID: {local_pubkey_id}")
        if mb.pubkey_id:
            if mb.pubkey_id == local_pubkey_id:
                print("  ✓ Matches server pubkey_id")
            else:
                print(f"  ⚠ Different from server pubkey_id: {mb.pubkey_id}")
    else:
        print("  ✗ No private key (run 'deadrop identity generate-keys' to create one)")

    # Server-side pubkey
    print("\nServer pubkey:")
    url = f"{cfg.url}/{ns}/identities/{identity_id}"
    headers = {"X-Inbox-Secret": mb.secret}
    response = httpx.get(url, headers=headers, timeout=30.0)

    if response.status_code >= 400:
        print(f"  Error fetching: {response.status_code}")
    else:
        identity = response.json()
        if identity.get("pubkey_id"):
            print(f"  Pubkey ID: {identity['pubkey_id']}")
            print(f"  Algorithm: {identity.get('algorithm', 'unknown')}")
            print(f"  Version: {identity.get('pubkey_version', 'unknown')}")
        else:
            print("  ✗ No public key registered on server")


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
    encrypt: bool | None = None,
    no_sign: bool = False,
):
    """Send a message to another identity.

    Uses the first mailbox in the namespace config, or specify --identity-id.

    Encryption: If sender has a keypair and recipient has a public key registered,
    the message will be encrypted by default. Use --encrypt=false to send plaintext.

    Signing: If sender has a keypair, messages are always signed (unless --no-sign).
    """
    from deadrop.crypto import (
        KeyPair,
        bytes_to_base64url,
        encrypt_message,
        pubkey_id,
        sign_message,
    )

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

    # Check sender keypair
    sender_keypair = None
    if sender.private_key:
        sender_keypair = KeyPair.from_private_key_base64(sender.private_key)

    # Get recipient's public key (fetch from server - server is authority)
    recipient_pubkey = None
    recipient_pubkey_id = None
    url = f"{cfg.url}/{ns}/identities/{to}"
    headers = {"X-Inbox-Secret": sender.secret}
    response = httpx.get(url, headers=headers, timeout=30.0)

    if response.status_code == 200:
        recipient_info = response.json()
        if recipient_info.get("public_key"):
            from deadrop.crypto import base64url_to_bytes

            recipient_pubkey = base64url_to_bytes(recipient_info["public_key"])
            recipient_pubkey_id = recipient_info.get("pubkey_id")

    # Determine if we should encrypt
    should_encrypt = False
    if encrypt is True:
        if not sender_keypair:
            print(
                "Error: --encrypt requires a keypair. Run 'deadrop identity generate-keys'",
                file=sys.stderr,
            )
            sys.exit(1)
        if not recipient_pubkey:
            print("Error: Recipient has no public key registered. Cannot encrypt.", file=sys.stderr)
            sys.exit(1)
        should_encrypt = True
    elif encrypt is False:
        should_encrypt = False
    else:
        # Auto-encrypt if both parties have keys
        should_encrypt = sender_keypair is not None and recipient_pubkey is not None

    # Build the message payload
    json_data: dict = {"to": to}
    if ttl is not None:
        json_data["ttl_hours"] = ttl

    message_body = body  # Body to sign (plaintext for plaintext msgs, or ciphertext for encrypted)

    if should_encrypt:
        # Encrypt the message (type guards ensure these are not None at this point)
        assert sender_keypair is not None
        assert recipient_pubkey is not None
        ciphertext = encrypt_message(body, recipient_pubkey, sender_keypair.private_key)
        message_body = bytes_to_base64url(ciphertext)
        json_data["body"] = message_body
        json_data["encrypted"] = True
        json_data["encryption"] = {
            "algorithm": "nacl-box",
            "recipient_pubkey_id": recipient_pubkey_id,
        }
        print("🔒 Encrypting message...")
    else:
        json_data["body"] = body
        json_data["encrypted"] = False
        if recipient_pubkey and not sender_keypair:
            print("⚠ Recipient has encryption key but you don't. Sending plaintext.")
            print("  Run 'deadrop identity generate-keys' to enable encryption.")

    # Sign the message (always, unless --no-sign)
    if sender_keypair and not no_sign:
        signature = sign_message(message_body, sender_keypair.private_key)
        sender_pubkey_id = pubkey_id(sender_keypair.public_key)
        json_data["signature"] = {
            "algorithm": "ed25519",
            "sender_pubkey_id": sender_pubkey_id,
            "value": bytes_to_base64url(signature),
        }
        print("✍ Signing message...")

    # Send message
    url = f"{cfg.url}/{ns}/send"
    headers = {"X-Inbox-Secret": sender.secret}

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
    raw: bool = False,
):
    """Read messages from an inbox.

    Uses the first mailbox in the namespace config, or specify identity-id.
    Reading marks messages as read and starts the TTL countdown.

    Encrypted messages are automatically decrypted if you have the private key.
    Signatures are verified when the sender's public key is available.

    --unread: Only show unread messages
    --after: Only show messages after this message ID (cursor for pagination)
    --raw: Show raw message data without decryption
    """
    from deadrop.crypto import (
        KeyPair,
        base64url_to_bytes,
        decrypt_message,
        verify_signature,
    )

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

    # Get recipient keypair (for decryption)
    recipient_keypair = None
    if mb.private_key:
        recipient_keypair = KeyPair.from_private_key_base64(mb.private_key)

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

    # Cache for sender info (fetched from server)
    sender_info_cache: dict[str, dict | None] = {}

    def get_sender_info(sender_id: str) -> dict | None:
        """Fetch sender's identity info from server (includes both encryption and signing keys)."""
        if sender_id in sender_info_cache:
            return sender_info_cache[sender_id]

        try:
            url = f"{cfg.url}/{ns}/identities/{sender_id}"
            headers = {"X-Inbox-Secret": mb.secret}
            resp = httpx.get(url, headers=headers, timeout=10.0)
            if resp.status_code == 200:
                info = resp.json()
                sender_info_cache[sender_id] = info
                return info
        except Exception:
            pass
        sender_info_cache[sender_id] = None
        return None

    for msg in messages:
        status = ""
        if msg.get("acked_at"):
            status = " [acked]"
        elif msg.get("read_at"):
            status = " [read]"
        else:
            status = " [unread]"

        # Encryption/signature status
        enc_status = ""
        sig_status = ""

        body = msg["body"]
        is_encrypted = msg.get("encrypted", False)

        if is_encrypted and not raw:
            if recipient_keypair:
                # Try to decrypt
                try:
                    # Get sender's encryption public key (X25519, not signing key)
                    sender_info = get_sender_info(msg["from"])
                    if sender_info and sender_info.get("public_key"):
                        sender_enc_pubkey = base64url_to_bytes(sender_info["public_key"])
                        ciphertext = base64url_to_bytes(msg["body"])
                        body = decrypt_message(
                            ciphertext, sender_enc_pubkey, recipient_keypair.private_key
                        )
                        enc_status = " 🔓"
                    else:
                        body = "[encrypted - sender pubkey not found]"
                        enc_status = " 🔒"
                except Exception as e:
                    body = f"[decryption failed: {e}]"
                    enc_status = " 🔒❌"
            else:
                body = "[encrypted - no private key]"
                enc_status = " 🔒"

        # Verify signature
        if msg.get("signature") and not raw:
            sig_meta = msg["signature"]
            sender_info = get_sender_info(msg["from"])
            sender_signing_key = None
            if sender_info and sender_info.get("signing_public_key"):
                sender_signing_key = base64url_to_bytes(sender_info["signing_public_key"])
            if sender_signing_key and sig_meta.get("value"):
                try:
                    sig_bytes = base64url_to_bytes(sig_meta["value"])
                    # Signature is over the original body (ciphertext for encrypted, plaintext for plain)
                    sig_body = msg["body"]
                    if verify_signature(sig_body, sig_bytes, sender_signing_key):
                        sig_status = " ✓verified"
                    else:
                        sig_status = " ⚠signature invalid"
                except Exception:
                    sig_status = " ⚠signature error"
            elif sig_meta.get("value"):
                sig_status = " (unverified - sender pubkey unknown)"

        # Try to resolve sender name from local config
        from_name = msg["from"]
        if msg["from"] in ns_cfg.mailboxes:
            mb_from = ns_cfg.mailboxes[msg["from"]]
            if mb_from.display_name:
                from_name = f"{mb_from.display_name} ({msg['from'][:8]}...)"

        print(f"--- {msg['mid'][:8]}...{status}{enc_status}{sig_status} ---")
        print(f"From: {from_name}")
        print(f"At:   {msg['created_at']}")
        print(f"\n{body}\n")


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


# --- Room Commands ---


@room_app.command
def room_create(
    ns: str,
    name: str,
    *,
    identity_id: str | None = None,
    encrypted: bool = False,
):
    """Create a new room.

    Creates a room and makes the caller the first member (and creator).

    --encrypted: Enable end-to-end encryption for this room.
                 Requires the creator to have a registered keypair.
                 All future members must also have keypairs.
    """
    ns_cfg = get_namespace_config(ns)
    cfg = get_config()

    # Find the creator identity
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
        print(f"Creating room as: {mb.display_name or mb.id}")

    # Check for keypair if encryption requested
    if encrypted and not mb.private_key:
        print("Error: Creating an encrypted room requires a keypair.", file=sys.stderr)
        print("Run 'deadrop identity generate-keys' first.", file=sys.stderr)
        sys.exit(1)

    # Create room via API
    url = f"{cfg.url}/{ns}/rooms"
    headers = {"X-Inbox-Secret": mb.secret}
    payload: dict = {"display_name": name}
    if encrypted:
        payload["encryption_enabled"] = True

        # True E2E: Generate secret locally, encrypt for self
        from .crypto import (
            generate_room_base_secret,
            encrypt_base_secret_for_member,
            KeyPair,
        )

        # Load keypair from local config
        if not mb.private_key:
            print("Error: No private key in local config.", file=sys.stderr)
            sys.exit(1)
        keypair = KeyPair.from_private_key_base64(mb.private_key)

        # Generate base secret locally (server never sees this!)
        base_secret = generate_room_base_secret()

        # We need room_id for encryption, but we don't have it yet.
        # Create room first without encryption, then initialize E2E
        payload["encryption_enabled"] = False
        response = httpx.post(url, headers=headers, json=payload, timeout=30.0)

        if response.status_code >= 400:
            print(f"Error {response.status_code}: {response.text}", file=sys.stderr)
            sys.exit(1)

        room = response.json()
        room_id = room["room_id"]

        # Now encrypt base_secret for ourselves
        encrypted_for_self = encrypt_base_secret_for_member(
            base_secret,
            keypair.public_key,
            keypair.private_key,
            room_id,
        )

        # Initialize E2E encryption on the room
        init_url = f"{cfg.url}/{ns}/rooms/{room_id}/initialize-e2e"
        init_payload = {
            "encrypted_base_secret": encrypted_for_self.hex(),
            "creator_public_key": keypair.public_key_base64,
        }
        init_response = httpx.post(init_url, headers=headers, json=init_payload, timeout=30.0)

        if init_response.status_code >= 400:
            print(
                f"Error initializing E2E: {init_response.status_code}: {init_response.text}",
                file=sys.stderr,
            )
            # Clean up: delete the room
            httpx.delete(f"{cfg.url}/{ns}/rooms/{room_id}", headers=headers, timeout=30.0)
            sys.exit(1)

        # Get updated room info
        room_response = httpx.get(f"{cfg.url}/{ns}/rooms/{room_id}", headers=headers, timeout=30.0)
        if room_response.status_code == 200:
            room = room_response.json()

        print("Room created!")
        print(f"  ID: {room['room_id']}")
        print(f"  Name: {room['display_name']}")
        print("  🔒 Encryption: enabled (true E2E)")
        print(f"  Epoch: {room.get('current_epoch_number', 0)}")
        return

    response = httpx.post(url, headers=headers, json=payload, timeout=30.0)

    if response.status_code >= 400:
        print(f"Error {response.status_code}: {response.text}", file=sys.stderr)
        sys.exit(1)

    room = response.json()

    print("Room created!")
    print(f"  ID: {room['room_id']}")
    print(f"  Name: {room['display_name']}")
    if encrypted:
        print("  🔒 Encryption: enabled")
        print(f"  Epoch: {room.get('current_epoch_number', 0)}")
    else:
        print("  Encryption: disabled")


@room_app.command
def room_list(
    ns: str,
    *,
    identity_id: str | None = None,
):
    """List rooms the identity is a member of."""
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

    url = f"{cfg.url}/{ns}/rooms"
    headers = {"X-Inbox-Secret": mb.secret}

    response = httpx.get(url, headers=headers, timeout=30.0)

    if response.status_code >= 400:
        print(f"Error {response.status_code}: {response.text}", file=sys.stderr)
        sys.exit(1)

    rooms = response.json()

    if not rooms:
        print("Not a member of any rooms.")
        return

    print(f"Rooms for {mb.display_name or mb.id}:")
    for room in rooms:
        enc_icon = "🔒" if room.get("encryption_enabled") else ""
        epoch = (
            f" (epoch {room.get('current_epoch_number', 0)})"
            if room.get("encryption_enabled")
            else ""
        )
        print(f"  {room['room_id']}  {room['display_name']} {enc_icon}{epoch}")


@room_app.command
def room_show(
    ns: str,
    room_id: str,
    *,
    identity_id: str | None = None,
):
    """Show room details."""
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

    url = f"{cfg.url}/{ns}/rooms/{room_id}"
    headers = {"X-Inbox-Secret": mb.secret}

    response = httpx.get(url, headers=headers, timeout=30.0)

    if response.status_code >= 400:
        print(f"Error {response.status_code}: {response.text}", file=sys.stderr)
        sys.exit(1)

    room = response.json()

    print(f"Room: {room['display_name']}")
    print(f"  ID: {room['room_id']}")
    print(f"  Created by: {room['created_by']}")
    print(f"  Created at: {room['created_at']}")
    if room.get("encryption_enabled"):
        print("  🔒 Encryption: enabled")
        print(f"  Current epoch: {room.get('current_epoch_number', 0)}")
    else:
        print("  Encryption: disabled")


@room_app.command
def room_epoch(
    ns: str,
    room_id: str,
    epoch_number: int | None = None,
    *,
    identity_id: str | None = None,
):
    """Show epoch information for an encrypted room.

    Without epoch_number, shows current epoch.
    With epoch_number, shows that specific epoch (for historical messages).
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

    if epoch_number is None:
        url = f"{cfg.url}/{ns}/rooms/{room_id}/epoch"
    else:
        url = f"{cfg.url}/{ns}/rooms/{room_id}/epoch/{epoch_number}"

    headers = {"X-Inbox-Secret": mb.secret}

    response = httpx.get(url, headers=headers, timeout=30.0)

    if response.status_code >= 400:
        print(f"Error {response.status_code}: {response.text}", file=sys.stderr)
        sys.exit(1)

    data = response.json()

    print(f"Epoch {data['epoch']['epoch_number']}:")
    print(f"  Epoch ID: {data['epoch']['epoch_id']}")
    print(f"  Reason: {data['epoch']['reason']}")
    print(f"  Membership hash: {data['epoch']['membership_hash'][:16]}...")
    print(f"  Created at: {data['epoch']['created_at']}")
    if data["epoch"].get("triggered_by"):
        print(f"  Triggered by: {data['epoch']['triggered_by']}")
    print(f"  Your encrypted key: {data['encrypted_epoch_key'][:32]}...")


@room_app.command
def room_rotate(
    ns: str,
    room_id: str,
    *,
    identity_id: str | None = None,
):
    """Manually rotate the encryption key for a room.

    Only the room creator can perform manual rotation.
    This is useful if you suspect key compromise.
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

    url = f"{cfg.url}/{ns}/rooms/{room_id}/rotate"
    headers = {"X-Inbox-Secret": mb.secret}

    response = httpx.post(url, headers=headers, timeout=30.0)

    if response.status_code >= 400:
        print(f"Error {response.status_code}: {response.text}", file=sys.stderr)
        sys.exit(1)

    data = response.json()

    print("Key rotated!")
    print(f"  New epoch: {data['epoch']['epoch_number']}")
    print(f"  Reason: {data['epoch']['reason']}")


@room_app.command
def room_members(
    ns: str,
    room_id: str,
    *,
    identity_id: str | None = None,
):
    """List members of a room."""
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

    url = f"{cfg.url}/{ns}/rooms/{room_id}/members"
    headers = {"X-Inbox-Secret": mb.secret}

    response = httpx.get(url, headers=headers, timeout=30.0)

    if response.status_code >= 400:
        print(f"Error {response.status_code}: {response.text}", file=sys.stderr)
        sys.exit(1)

    members = response.json()

    if not members:
        print("No members (this shouldn't happen).")
        return

    print(f"Members ({len(members)}):")
    for member in members:
        print(f"  {member['identity_id']}  (joined {member['joined_at']})")


@room_app.command
def room_invite(
    ns: str,
    room_id: str,
    member_id: str,
    *,
    identity_id: str | None = None,
):
    """Add a member to a room.

    For encrypted rooms, the invitee must have a registered keypair.
    For true E2E rooms, this command generates a new secret and
    distributes it to all members (including the new one).
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

    headers = {"X-Inbox-Secret": mb.secret}

    # Check if this is a true E2E room (no server-side base_secret)
    room_url = f"{cfg.url}/{ns}/rooms/{room_id}"
    room_response = httpx.get(room_url, headers=headers, timeout=30.0)
    if room_response.status_code >= 400:
        print(f"Error getting room: {room_response.status_code}", file=sys.stderr)
        sys.exit(1)

    room_info = room_response.json()
    is_encrypted = room_info.get("encryption_enabled", False)

    # Add member first
    url = f"{cfg.url}/{ns}/rooms/{room_id}/members"
    payload = {"identity_id": member_id}
    response = httpx.post(url, headers=headers, json=payload, timeout=30.0)

    if response.status_code >= 400:
        print(f"Error {response.status_code}: {response.text}", file=sys.stderr)
        sys.exit(1)

    data = response.json()

    # For E2E encrypted rooms, we need to do client-side key distribution
    # Check if the room is in true E2E mode by trying to get our member secret
    if is_encrypted:
        member_secret_url = f"{cfg.url}/{ns}/rooms/{room_id}/member-secret"
        secret_response = httpx.get(member_secret_url, headers=headers, timeout=30.0)

        if secret_response.status_code == 200:
            # True E2E mode: we have an encrypted secret stored
            from .crypto import (
                generate_room_base_secret,
                encrypt_base_secret_for_member,
                base64url_to_bytes,
                KeyPair,
            )

            # Load our keypair
            if not mb.private_key:
                print("Error: No private key in local config.", file=sys.stderr)
                print("The member was added but secret distribution failed.", file=sys.stderr)
                sys.exit(1)
            keypair = KeyPair.from_private_key_base64(mb.private_key)

            # Generate fresh secret for the new epoch (forward secrecy)
            new_base_secret = generate_room_base_secret()

            # Get all current members' public keys
            members_url = f"{cfg.url}/{ns}/rooms/{room_id}/members"
            members_response = httpx.get(members_url, headers=headers, timeout=30.0)
            if members_response.status_code >= 400:
                print(f"Error getting members: {members_response.status_code}", file=sys.stderr)
                sys.exit(1)

            members = members_response.json()

            # Build encrypted secrets for all members
            member_secrets = []
            for member in members:
                mid = member["identity_id"]
                # Get member's public key
                identity_url = f"{cfg.url}/{ns}/identities/{mid}"
                id_response = httpx.get(identity_url, headers=headers, timeout=30.0)
                if id_response.status_code >= 400:
                    print(
                        f"Error getting identity {mid}: {id_response.status_code}", file=sys.stderr
                    )
                    continue

                id_info = id_response.json()
                member_pubkey_b64 = id_info.get("public_key")
                if not member_pubkey_b64:
                    print(f"Warning: Member {mid} has no public key, skipping", file=sys.stderr)
                    continue

                member_pubkey = base64url_to_bytes(member_pubkey_b64)

                # Encrypt new secret for this member
                encrypted = encrypt_base_secret_for_member(
                    new_base_secret,
                    member_pubkey,
                    keypair.private_key,
                    room_id,
                )
                member_secrets.append(
                    {
                        "identity_id": mid,
                        "encrypted_base_secret": encrypted.hex(),
                        "inviter_public_key": keypair.public_key_base64,
                    }
                )

            # Get current secret version
            current_version = room_info.get("current_epoch_number", 0)

            # Rotate the secret
            rotate_url = f"{cfg.url}/{ns}/rooms/{room_id}/rotate-secret"
            rotate_payload = {
                "new_secret_version": current_version + 1,
                "member_secrets": member_secrets,
            }
            rotate_response = httpx.post(
                rotate_url, headers=headers, json=rotate_payload, timeout=30.0
            )

            if rotate_response.status_code >= 400:
                print(
                    f"Error rotating secret: {rotate_response.status_code}: {rotate_response.text}",
                    file=sys.stderr,
                )
                print("The member was added but secret distribution failed.", file=sys.stderr)
                sys.exit(1)

            rotate_data = rotate_response.json()
            print(f"Added {member_id} to room.")
            print(f"New epoch: {rotate_data.get('secret_version', current_version + 1)}")
            return

    # Server-mediated mode or non-encrypted room
    print(f"Added {member_id} to room.")
    if "current_epoch_number" in data:
        print(f"New epoch: {data['current_epoch_number']}")


@room_app.command
def room_leave(
    ns: str,
    room_id: str,
    *,
    identity_id: str | None = None,
):
    """Leave a room."""
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

    url = f"{cfg.url}/{ns}/rooms/{room_id}/members/{mb.id}"
    headers = {"X-Inbox-Secret": mb.secret}

    response = httpx.delete(url, headers=headers, timeout=30.0)

    if response.status_code >= 400:
        print(f"Error {response.status_code}: {response.text}", file=sys.stderr)
        sys.exit(1)

    print("Left room.")


@room_app.command
def room_send(
    ns: str,
    room_id: str,
    body: str,
    *,
    identity_id: str | None = None,
    encrypt: bool | None = None,
):
    """Send a message to a room.

    For encrypted rooms, the message is automatically encrypted with the
    current epoch key. If a 409 conflict is returned (epoch mismatch),
    the command will automatically retry with the new epoch.

    --encrypt: Force encryption on (requires encrypted room)
    """
    from deadrop.crypto import (
        KeyPair,
        base64url_to_bytes,
        bytes_to_base64url,
        encrypt_room_message,
    )

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

    # Check if room is encrypted
    room_url = f"{cfg.url}/{ns}/rooms/{room_id}"
    headers = {"X-Inbox-Secret": mb.secret}
    room_resp = httpx.get(room_url, headers=headers, timeout=30.0)

    if room_resp.status_code >= 400:
        print(f"Error {room_resp.status_code}: {room_resp.text}", file=sys.stderr)
        sys.exit(1)

    room = room_resp.json()
    is_encrypted = room.get("encryption_enabled", False)

    if encrypt and not is_encrypted:
        print("Error: Room is not encrypted. Cannot use --encrypt.", file=sys.stderr)
        sys.exit(1)

    if is_encrypted:
        # Need keypair for signing/encryption
        if not mb.private_key:
            print("Error: Encrypted room requires a keypair.", file=sys.stderr)
            print("Run 'deadrop identity generate-keys' first.", file=sys.stderr)
            sys.exit(1)

        keypair = KeyPair.from_private_key_base64(mb.private_key)

        # Check if this is a true E2E room (has member-secret endpoint)
        member_secret_url = f"{cfg.url}/{ns}/rooms/{room_id}/member-secret"
        secret_resp = httpx.get(member_secret_url, headers=headers, timeout=30.0)

        if secret_resp.status_code == 200:
            # True E2E mode: derive epoch key from base secret
            from .crypto import (
                decrypt_base_secret_from_invite,
                derive_epoch_key,
                compute_membership_hash,
            )

            secret_data = secret_resp.json()
            encrypted_base_secret = bytes.fromhex(secret_data["encrypted_base_secret"])
            inviter_pubkey = base64url_to_bytes(secret_data["inviter_public_key"])
            secret_version = secret_data["secret_version"]

            # Decrypt our base secret
            base_secret = decrypt_base_secret_from_invite(
                encrypted_base_secret,
                inviter_pubkey,
                keypair.private_key,
                room_id,
            )

            # Get current members to compute membership hash
            members_url = f"{cfg.url}/{ns}/rooms/{room_id}/members"
            members_resp = httpx.get(members_url, headers=headers, timeout=30.0)
            if members_resp.status_code >= 400:
                print(f"Error getting members: {members_resp.status_code}", file=sys.stderr)
                sys.exit(1)

            members = members_resp.json()
            member_ids = sorted([m["identity_id"] for m in members])
            membership_hash = compute_membership_hash(member_ids)

            # Derive epoch key
            epoch_number = secret_version
            epoch_key = derive_epoch_key(base_secret, epoch_number, room_id, membership_hash)

        else:
            # Server-mediated mode: get epoch key from server
            epoch_url = f"{cfg.url}/{ns}/rooms/{room_id}/epoch"
            epoch_resp = httpx.get(epoch_url, headers=headers, timeout=30.0)

            if epoch_resp.status_code >= 400:
                print(f"Error getting epoch: {epoch_resp.status_code}", file=sys.stderr)
                sys.exit(1)

            epoch_data = epoch_resp.json()
            epoch_number = epoch_data["epoch"]["epoch_number"]
            encrypted_key = epoch_data["encrypted_epoch_key"]
            distributor_pubkey = epoch_data.get("distributor_public_key")

            # Decrypt the epoch key using our private key and server's public key
            from .crypto import decrypt_epoch_key

            encrypted_key_bytes = base64url_to_bytes(encrypted_key)
            if distributor_pubkey and len(encrypted_key_bytes) > 32:
                # Key is encrypted - decrypt it
                distributor_pubkey_bytes = base64url_to_bytes(distributor_pubkey)
                epoch_key = decrypt_epoch_key(
                    encrypted_epoch_key=encrypted_key_bytes,
                    distributor_public_key=distributor_pubkey_bytes,
                    member_private_key=keypair.private_key,
                )
            else:
                # Fallback for unencrypted keys (legacy/test mode)
                epoch_key = encrypted_key_bytes

        # Encrypt the message
        encrypted_msg = encrypt_room_message(
            plaintext=body,
            epoch_key=epoch_key,
            sender_signing_key=keypair.private_key,
            room_id=room_id,
            epoch_number=epoch_number,
        )

        # Send encrypted message
        send_url = f"{cfg.url}/{ns}/rooms/{room_id}/messages"
        payload: dict = {
            "body": bytes_to_base64url(encrypted_msg.ciphertext),
            "epoch_number": epoch_number,
            "encrypted": True,
            "encryption_meta": json.dumps(
                {
                    "algorithm": "xsalsa20-poly1305+ed25519",
                    "nonce": bytes_to_base64url(encrypted_msg.nonce),
                }
            ),
            "signature": bytes_to_base64url(encrypted_msg.signature),
        }

        response = httpx.post(send_url, headers=headers, json=payload, timeout=30.0)

        # Handle epoch mismatch - retry with new epoch
        if response.status_code == 409:
            print("Epoch mismatch - fetching new key and retrying...")
            error_data = response.json()
            new_epoch = error_data.get("expected_epoch")

            # Get new epoch key
            epoch_url = f"{cfg.url}/{ns}/rooms/{room_id}/epoch/{new_epoch}"
            epoch_resp = httpx.get(epoch_url, headers=headers, timeout=30.0)

            if epoch_resp.status_code >= 400:
                print(f"Error getting new epoch: {epoch_resp.status_code}", file=sys.stderr)
                sys.exit(1)

            epoch_data = epoch_resp.json()
            epoch_number = new_epoch
            encrypted_key = epoch_data["encrypted_epoch_key"]
            distributor_pubkey = epoch_data.get("distributor_public_key")
            encrypted_key_bytes = base64url_to_bytes(encrypted_key)
            if distributor_pubkey and len(encrypted_key_bytes) > 32:
                distributor_pubkey_bytes = base64url_to_bytes(distributor_pubkey)
                epoch_key = decrypt_epoch_key(
                    encrypted_epoch_key=encrypted_key_bytes,
                    distributor_public_key=distributor_pubkey_bytes,
                    member_private_key=keypair.private_key,
                )
            else:
                epoch_key = encrypted_key_bytes

            # Re-encrypt with new epoch
            encrypted_msg = encrypt_room_message(
                plaintext=body,
                epoch_key=epoch_key,
                sender_signing_key=keypair.private_key,
                room_id=room_id,
                epoch_number=epoch_number,
            )

            payload = {
                "body": bytes_to_base64url(encrypted_msg.ciphertext),
                "epoch_number": epoch_number,
                "encrypted": True,
                "encryption_meta": json.dumps(
                    {
                        "algorithm": "xsalsa20-poly1305+ed25519",
                        "nonce": bytes_to_base64url(encrypted_msg.nonce),
                    }
                ),
                "signature": bytes_to_base64url(encrypted_msg.signature),
            }

            response = httpx.post(send_url, headers=headers, json=payload, timeout=30.0)

        if response.status_code >= 400:
            print(f"Error {response.status_code}: {response.text}", file=sys.stderr)
            sys.exit(1)

        msg = response.json()
        print(f"🔒 Encrypted message sent: {msg['mid']}")

    else:
        # Unencrypted room - send plaintext
        send_url = f"{cfg.url}/{ns}/rooms/{room_id}/messages"
        payload = {"body": body}

        response = httpx.post(send_url, headers=headers, json=payload, timeout=30.0)

        if response.status_code >= 400:
            print(f"Error {response.status_code}: {response.text}", file=sys.stderr)
            sys.exit(1)

        msg = response.json()
        print(f"Message sent: {msg['mid']}")


@room_app.command
def room_messages(
    ns: str,
    room_id: str,
    *,
    identity_id: str | None = None,
    limit: int = 50,
    decrypt: bool = True,
    raw: bool = False,
):
    """Read messages from a room.

    For encrypted rooms, messages are automatically decrypted if you have
    the epoch keys (fetched from server and decrypted with your private key).

    --limit: Maximum number of messages to show
    --decrypt: Decrypt messages (default: true)
    --raw: Show raw message data
    """
    from deadrop.crypto import (
        KeyPair,
        base64url_to_bytes,
        decrypt_room_message,
        EncryptedRoomMessage,
    )

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

    # Get keypair if we have one
    keypair = None
    if mb.private_key:
        keypair = KeyPair.from_private_key_base64(mb.private_key)

    # Get room info
    room_url = f"{cfg.url}/{ns}/rooms/{room_id}"
    headers = {"X-Inbox-Secret": mb.secret}
    room_resp = httpx.get(room_url, headers=headers, timeout=30.0)

    if room_resp.status_code >= 400:
        print(f"Error {room_resp.status_code}: {room_resp.text}", file=sys.stderr)
        sys.exit(1)

    room = room_resp.json()

    # Get messages
    messages_url = f"{cfg.url}/{ns}/rooms/{room_id}/messages?limit={limit}"
    response = httpx.get(messages_url, headers=headers, timeout=30.0)

    if response.status_code >= 400:
        print(f"Error {response.status_code}: {response.text}", file=sys.stderr)
        sys.exit(1)

    messages_data = response.json()
    # Handle both {"messages": [...]} and direct list formats
    if isinstance(messages_data, dict) and "messages" in messages_data:
        messages = messages_data["messages"]
    else:
        messages = messages_data

    if raw:
        print_json(messages_data)
        return

    if not messages:
        print("No messages.")
        return

    # Cache for epoch keys
    epoch_keys: dict[int, bytes] = {}

    # Cache for sender signing keys
    sender_keys: dict[str, bytes | None] = {}

    def get_sender_signing_key(sender_id: str) -> bytes | None:
        """Get sender's signing public key from server."""
        if sender_id in sender_keys:
            return sender_keys[sender_id]

        try:
            url = f"{cfg.url}/{ns}/identities/{sender_id}"
            resp = httpx.get(url, headers=headers, timeout=10.0)
            if resp.status_code == 200:
                info = resp.json()
                if info.get("signing_public_key"):
                    key = base64url_to_bytes(info["signing_public_key"])
                    sender_keys[sender_id] = key
                    return key
        except Exception:
            pass
        sender_keys[sender_id] = None
        return None

    def get_epoch_key(epoch_num: int) -> bytes | None:
        """Get epoch key from cache or server."""
        if epoch_num in epoch_keys:
            return epoch_keys[epoch_num]

        try:
            url = f"{cfg.url}/{ns}/rooms/{room_id}/epoch/{epoch_num}"
            resp = httpx.get(url, headers=headers, timeout=10.0)
            if resp.status_code == 200:
                data = resp.json()
                encrypted_key = data["encrypted_epoch_key"]
                distributor_pubkey = data.get("distributor_public_key")
                encrypted_key_bytes = base64url_to_bytes(encrypted_key)

                if distributor_pubkey and len(encrypted_key_bytes) > 32:
                    # Key is encrypted - decrypt it
                    from .crypto import decrypt_epoch_key

                    distributor_pubkey_bytes = base64url_to_bytes(distributor_pubkey)
                    key = decrypt_epoch_key(
                        encrypted_epoch_key=encrypted_key_bytes,
                        distributor_public_key=distributor_pubkey_bytes,
                        member_private_key=keypair.private_key,
                    )
                else:
                    key = encrypted_key_bytes

                epoch_keys[epoch_num] = key
                return key
        except Exception:
            pass
        return None

    print(f"Messages in {room['display_name']}:")
    print()

    for msg in messages:
        from_id = msg["from_id"]
        body = msg["body"]
        enc_status = ""
        sig_status = ""

        if msg.get("encrypted") and decrypt and keypair:
            epoch_num = msg.get("epoch_number")
            if epoch_num is not None:
                epoch_key = get_epoch_key(epoch_num)
                if epoch_key:
                    try:
                        # Reconstruct EncryptedRoomMessage
                        meta = json.loads(msg.get("encryption_meta", "{}"))
                        encrypted_msg = EncryptedRoomMessage(
                            ciphertext=base64url_to_bytes(msg["body"]),
                            nonce=base64url_to_bytes(meta.get("nonce", "")),
                            signature=base64url_to_bytes(msg.get("signature", "")),
                        )

                        # Get sender's signing key
                        sender_key = get_sender_signing_key(from_id)
                        if sender_key:
                            body = decrypt_room_message(
                                encrypted_msg,
                                epoch_key,
                                sender_key,
                                room_id,
                                epoch_num,
                            )
                            enc_status = " 🔓"
                            sig_status = " ✓"
                        else:
                            body = "[encrypted - sender key not found]"
                            enc_status = " 🔒"
                    except Exception as e:
                        body = f"[decryption failed: {e}]"
                        enc_status = " 🔒❌"
                else:
                    body = f"[encrypted - epoch {epoch_num} key not available]"
                    enc_status = " 🔒"
        elif msg.get("encrypted"):
            body = "[encrypted - no keypair]"
            enc_status = " 🔒"

        print(f"[{msg['created_at']}] {from_id[:8]}...:{enc_status}{sig_status}")
        print(f"  {body}")
        print()


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
