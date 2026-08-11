"""OAuth 2.1 authorization server for the MCP endpoint.

claude.ai's remote-connector auth types are ``oauth_dcr``, ``oauth_cimd``,
``oauth_anthropic_creds`` and ``static_headers``. Only the first needs nothing
from Anthropic and nothing hosted by the client, so this module implements it:
RFC 9728 protected-resource metadata, RFC 8414 authorization-server metadata,
RFC 7591 dynamic client registration, and an authorization-code flow with
mandatory PKCE S256 and rotating refresh tokens.

An issued token is **identity-scoped**. The consent step is where a human
proves possession of a deaddrop inbox secret, and the grant records the
``(ns, identity_id)`` that secret derives to; every tool call made with a token
from that grant presents that identity's secret to the room routes. So a token
is not a key to the server, it is a key to one identity in one namespace, and
the room-membership model does the rest of the enforcement unchanged.

Configuration:

``DEADROP_MCP_PUBLIC_URL``
    Origin the server is reachable at, e.g. ``https://deaddrop.example``. The
    issuer and the RFC 8707 resource identifier are derived from it. It is
    explicit config rather than a value reconstructed from request headers
    because the Procfile runs uvicorn without ``--proxy-headers``.
``DEADROP_MCP_OAUTH_KEY``
    base64url-encoded 32-byte AES-256-GCM key sealing inbox secrets at rest.
"""

from __future__ import annotations

import hashlib
import html
import logging
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode, urlparse, urlsplit, urlunsplit

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

from . import crypto, db, instrument
from .auth import derive_id, hash_secret

logger = logging.getLogger(__name__)

MCP_PATH = "/mcp"
BASE_SCOPE = "mcp"
OFFLINE_SCOPE = "offline_access"
SCOPES_SUPPORTED = [BASE_SCOPE, OFFLINE_SCOPE]

# An authorization code is redeemed by the client immediately after the
# redirect. OAuth 2.1 puts the ceiling at 10 minutes; a minute is ample and
# shrinks the window in which a code leaked through a referrer is useful.
CODE_TTL = timedelta(seconds=60)
ACCESS_TTL = timedelta(hours=1)
REFRESH_TTL = timedelta(days=30)

# Deliberately not under ``/mcp/``: ``POST /mcp/{ns}/{secret}`` would shadow
# ``/mcp/oauth/token`` as a namespace called "oauth" whenever these routes are
# not registered, and a route that means two things depending on configuration
# is a route waiting to be misread.
AUTHORIZE_PATH = "/oauth/authorize"
TOKEN_PATH = "/oauth/token"
REGISTER_PATH = "/oauth/register"


@dataclass(frozen=True)
class OAuthConfig:
    """Resolved authorization-server configuration."""

    public_url: str
    key: bytes

    @property
    def issuer(self) -> str:
        return self.public_url

    @property
    def resource(self) -> str:
        return f"{self.public_url}{MCP_PATH}"

    @property
    def resource_metadata_url(self) -> str:
        return f"{self.public_url}/.well-known/oauth-protected-resource"


def load_config() -> OAuthConfig | None:
    """Read config from the environment, or None when OAuth is not configured.

    Absent config leaves the ``/mcp/{ns}/{secret}`` route as the only way in:
    no metadata is advertised, no endpoints are mounted, and a ``401`` from
    ``POST /mcp`` carries no ``resource_metadata`` pointer to an authorization
    server that does not exist.
    """
    public_url = os.environ.get("DEADROP_MCP_PUBLIC_URL", "").strip().rstrip("/")
    key_b64 = os.environ.get("DEADROP_MCP_OAUTH_KEY", "").strip()
    if not (public_url and key_b64):
        return None
    try:
        key = crypto.base64url_to_bytes(key_b64)
    except Exception:
        logger.error("DEADROP_MCP_OAUTH_KEY is not valid base64url; OAuth disabled")
        return None
    if len(key) != 32:
        logger.error("DEADROP_MCP_OAUTH_KEY must decode to 32 bytes; OAuth disabled")
        return None

    return OAuthConfig(public_url=public_url, key=key)


# --- Small helpers -----------------------------------------------------


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _expired(stamp: str | None) -> bool:
    """True when an ISO-8601 timestamp is in the past. A bad value is expired."""
    if not stamp:
        return True
    try:
        parsed = datetime.fromisoformat(stamp)
    except ValueError:
        return True
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed <= _now()


def _new_token() -> str:
    return secrets.token_urlsafe(32)


def _pkce_matches(verifier: str, challenge: str) -> bool:
    """Verify an S256 PKCE code_verifier against the stored challenge."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return secrets.compare_digest(crypto.bytes_to_base64url(digest), challenge)


def _canonical(uri: str) -> str:
    """Lowercase scheme and host, drop a trailing slash on an empty path.

    The MCP spec asks clients to send a canonical resource URI but tells
    servers to accept uppercase scheme and host for robustness, so comparison
    normalises rather than rejecting.
    """
    parts = urlsplit(uri.strip())
    path = parts.path.rstrip("/") if parts.path in ("", "/") else parts.path
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), path, parts.query, ""))


def _resource_ok(presented: str | None, cfg: OAuthConfig) -> bool:
    """Accept an absent ``resource`` but never a mismatched one.

    RFC 8707 is a MUST on the client, so an absent parameter means a client
    that predates it and can only be talking about the one resource this
    server has. A *wrong* value means the client is asking for a token
    audienced at something else, which is exactly what audience binding exists
    to refuse.
    """
    if not presented:
        return True
    return _canonical(presented) == _canonical(cfg.resource)


def _redirect_ok(presented: str, registered: list[str]) -> bool:
    """Exact match, except that a loopback redirect ignores the port.

    RFC 8252 section 7.3 requires the port to be ignored for ``127.0.0.1``,
    and Claude Code binds an ephemeral port per session while declaring a
    portless ``http://localhost/callback``, so the same relaxation is applied
    to ``localhost``. Every other redirect URI is compared byte for byte.
    """
    if presented in registered:
        return True
    got = urlparse(presented)
    if got.hostname not in ("127.0.0.1", "::1", "localhost"):
        return False
    for candidate in registered:
        want = urlparse(candidate)
        if want.hostname == got.hostname and want.scheme == got.scheme and want.path == got.path:
            return True
    return False


def _oauth_error(status: int, error: str, description: str) -> JSONResponse:
    """An RFC 6749 section 5.2 error body."""
    instrument.sink.counter("mcp.oauth.error", tags={"error": error})
    return JSONResponse(
        {"error": error, "error_description": description},
        status_code=status,
        headers={"Cache-Control": "no-store"},
    )


# --- Metadata documents ------------------------------------------------


def protected_resource_metadata(cfg: OAuthConfig) -> dict:
    """RFC 9728. ``resource`` must equal the URL the operator typed, exactly."""
    return {
        "resource": cfg.resource,
        "authorization_servers": [cfg.issuer],
        "scopes_supported": SCOPES_SUPPORTED,
        "bearer_methods_supported": ["header"],
        "resource_name": "deaddrop rooms",
    }


def authorization_server_metadata(cfg: OAuthConfig) -> dict:
    """RFC 8414.

    ``client_id_metadata_document_supported`` is deliberately absent: claude.ai
    selects CIMD only when it is advertised together with a ``none`` token
    endpoint auth method, and falls back to dynamic client registration
    otherwise. Advertising a mechanism this server does not implement would
    strand the flow.
    """
    return {
        "issuer": cfg.issuer,
        "authorization_endpoint": f"{cfg.public_url}{AUTHORIZE_PATH}",
        "token_endpoint": f"{cfg.public_url}{TOKEN_PATH}",
        "registration_endpoint": f"{cfg.public_url}{REGISTER_PATH}",
        "scopes_supported": SCOPES_SUPPORTED,
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["none"],
        "code_challenge_methods_supported": ["S256"],
    }


# --- Dynamic client registration (RFC 7591) ----------------------------


async def handle_register(request: Request) -> Response:
    """Register a client. claude.ai calls this on every fresh connection."""
    try:
        body = await request.json()
    except Exception:
        return _oauth_error(400, "invalid_client_metadata", "body must be JSON")
    if not isinstance(body, dict):
        return _oauth_error(400, "invalid_client_metadata", "body must be a JSON object")

    redirect_uris = body.get("redirect_uris")
    if not isinstance(redirect_uris, list) or not redirect_uris:
        return _oauth_error(400, "invalid_redirect_uri", "redirect_uris is required")
    if not all(isinstance(u, str) and u for u in redirect_uris):
        return _oauth_error(400, "invalid_redirect_uri", "redirect_uris must be strings")
    for uri in redirect_uris:
        parts = urlparse(uri)
        loopback = parts.hostname in ("127.0.0.1", "::1", "localhost")
        if parts.scheme == "https" or (parts.scheme == "http" and loopback):
            continue
        return _oauth_error(
            400, "invalid_redirect_uri", f"redirect_uri must be https or loopback http: {uri}"
        )
    if any("#" in uri for uri in redirect_uris):
        return _oauth_error(400, "invalid_redirect_uri", "redirect_uri must not have a fragment")

    grant_types = body.get("grant_types") or ["authorization_code", "refresh_token"]
    unsupported = set(grant_types) - {"authorization_code", "refresh_token"}
    if unsupported:
        return _oauth_error(
            400, "invalid_client_metadata", f"unsupported grant_types: {sorted(unsupported)}"
        )
    response_types = body.get("response_types") or ["code"]
    if set(response_types) - {"code"}:
        return _oauth_error(400, "invalid_client_metadata", "only response_type=code is supported")

    # Public client only. A confidential client would need a secret returned in
    # this response and stored here, and every client this server has is a
    # browser-driven or CLI-driven public client that cannot keep one.
    if body.get("token_endpoint_auth_method", "none") != "none":
        return _oauth_error(
            400,
            "invalid_client_metadata",
            "only token_endpoint_auth_method=none (public client) is supported",
        )

    client_id = f"dcr_{secrets.token_urlsafe(24)}"
    client_name = body.get("client_name")
    client = db.create_oauth_client(
        client_id=client_id,
        redirect_uris=redirect_uris,
        grant_types=sorted(grant_types),
        response_types=sorted(response_types),
        token_endpoint_auth_method="none",
        client_name=client_name if isinstance(client_name, str) else None,
        scope=BASE_SCOPE,
        metadata={k: v for k, v in body.items() if k in ("client_uri", "logo_uri", "software_id")},
    )
    instrument.sink.counter("mcp.oauth.register")
    logger.info("MCP OAuth client registered: %s (%s)", client_id, client.get("client_name"))
    return JSONResponse(
        {
            "client_id": client_id,
            "client_id_issued_at": int(_now().timestamp()),
            "client_name": client.get("client_name"),
            "redirect_uris": redirect_uris,
            "grant_types": sorted(grant_types),
            "response_types": sorted(response_types),
            "token_endpoint_auth_method": "none",
            "scope": BASE_SCOPE,
        },
        status_code=201,
        headers={"Cache-Control": "no-store"},
    )


# --- Authorization endpoint --------------------------------------------


def _requested_scope(raw: str | None) -> str | None:
    """Intersect the requested scope with what is supported, or None if empty.

    An unknown scope is dropped rather than refused: claude.ai composes the
    scope set from metadata plus ``offline_access``, and refusing the whole
    request over one unrecognised entry turns a cosmetic mismatch into a failed
    connection.
    """
    requested = (raw or BASE_SCOPE).split()
    granted = [s for s in SCOPES_SUPPORTED if s in requested]
    return " ".join(granted) or None


async def handle_authorize_get(request: Request) -> Response:
    """Validate an authorization request and render the consent page."""
    cfg = _require_config(request)
    params = request.query_params
    client_id = params.get("client_id", "")
    redirect_uri = params.get("redirect_uri", "")

    client = db.get_oauth_client(client_id) if client_id else None
    if client is None:
        return _consent_error(400, "Unknown client. Re-add the connector to register again.")
    if not redirect_uri or not _redirect_ok(redirect_uri, client["redirect_uris"]):
        # Never redirect to an unvalidated URI — that is the open-redirector.
        return _consent_error(400, "redirect_uri does not match this client's registration.")

    state = params.get("state")
    if params.get("response_type") != "code":
        return _redirect_error(redirect_uri, "unsupported_response_type", state)
    challenge = params.get("code_challenge", "")
    if params.get("code_challenge_method") != "S256" or not challenge:
        return _redirect_error(
            redirect_uri, "invalid_request", state, "code_challenge with S256 is required"
        )
    if not _resource_ok(params.get("resource"), cfg):
        return _redirect_error(
            redirect_uri, "invalid_target", state, f"resource must be {cfg.resource}"
        )
    scope = _requested_scope(params.get("scope"))
    if scope is None:
        return _redirect_error(redirect_uri, "invalid_scope", state)

    return _consent_page(client, redirect_uri, state, challenge, scope)


def _consent_error(status: int, message: str) -> HTMLResponse:
    """Render an error the client cannot be redirected with."""
    instrument.sink.counter("mcp.oauth.consent_error")
    return HTMLResponse(
        f"<!doctype html><title>deaddrop — authorization</title>"
        f"<h1>Authorization failed</h1><p>{html.escape(message)}</p>",
        status_code=status,
    )


def _redirect_error(
    redirect_uri: str, error: str, state: str | None, description: str | None = None
) -> RedirectResponse:
    """Send an OAuth error back to a redirect URI that has been validated."""
    instrument.sink.counter("mcp.oauth.error", tags={"error": error})
    query = {"error": error}
    if description:
        query["error_description"] = description
    if state:
        query["state"] = state
    joiner = "&" if urlparse(redirect_uri).query else "?"
    return RedirectResponse(f"{redirect_uri}{joiner}{urlencode(query)}", status_code=302)


def _consent_page(
    client: dict,
    redirect_uri: str,
    state: str | None,
    challenge: str,
    scope: str,
) -> HTMLResponse:
    """The consent form.

    The identity is chosen here, by pasting the inbox secret of the identity the
    token should act as. Possession of that secret is both the authentication
    and the selection, so there is no separate login and no second credential
    store: the same ``verify_identity_secret`` the room routes call decides
    whether consent is valid.

    The redirect host is displayed prominently because the MCP spec requires
    it — a Client ID Metadata Document or a dynamic registration cannot stop a
    local process from claiming to be a legitimate client, so the human is the
    check on where the code is about to be sent.
    """
    name = html.escape(client.get("client_name") or client["client_id"])
    host = html.escape(urlparse(redirect_uri).netloc or redirect_uri)
    loopback = urlparse(redirect_uri).hostname in ("127.0.0.1", "::1", "localhost")
    warning = (
        "<p class='warn'>This is a loopback address — the code will be sent to a program "
        "running on the machine you are using now. Only approve if you started it.</p>"
        if loopback
        else ""
    )
    hidden = "".join(
        f"<input type='hidden' name='{k}' value='{html.escape(v)}'>"
        for k, v in (
            ("client_id", client["client_id"]),
            ("redirect_uri", redirect_uri),
            ("state", state or ""),
            ("code_challenge", challenge),
            ("scope", scope),
        )
    )
    return HTMLResponse(
        f"""<!doctype html><html><head><meta charset="utf-8">
<title>deaddrop — authorize {name}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
 body {{ font-family: Georgia, serif; max-width: 34rem; margin: 3rem auto; padding: 0 1rem;
        color: #1c1c1c; background: #faf7f0; line-height: 1.5; }}
 code, input {{ font-family: ui-monospace, monospace; }}
 hr {{ border: 0; border-top: 1px solid #cfc6b3; margin: 1.5rem 0; }}
 label {{ display: block; margin: 1rem 0 0.25rem; }}
 input[type=text], input[type=password] {{ width: 100%; padding: 0.5rem; box-sizing: border-box;
        border: 1px solid #cfc6b3; background: #fff; }}
 .warn {{ background: #fdf1e6; border-left: 3px solid #8a3324; padding: 0.5rem 0.75rem; }}
 button {{ font: inherit; padding: 0.5rem 1.25rem; margin-top: 1.25rem; cursor: pointer; }}
 .primary {{ background: #2f4f4f; color: #faf7f0; border: 0; }}
</style></head><body>
<h1>Authorize <em>{name}</em></h1>
<p><strong>{name}</strong> is asking to read and post messages in deaddrop rooms
on behalf of one identity. The authorization code will be sent to
<code>{host}</code>.</p>
{warning}
<hr>
<p>Paste the inbox secret of the identity this connector should act as. The token
issued will be able to do exactly what that identity can do, and nothing else.</p>
<form method="post" action="{AUTHORIZE_PATH}">
{hidden}
<label for="ns">Namespace</label>
<input type="text" id="ns" name="ns" autocomplete="off" spellcheck="false" required>
<label for="inbox_secret">Inbox secret</label>
<input type="password" id="inbox_secret" name="inbox_secret" autocomplete="off" required>
<p><small>Scope: <code>{html.escape(scope)}</code></small></p>
<button type="submit" name="action" value="approve" class="primary">Approve</button>
<button type="submit" name="action" value="deny">Deny</button>
</form>
</body></html>""",
        headers={"Cache-Control": "no-store"},
    )


async def handle_authorize_post(request: Request) -> Response:
    """Consent submission: verify the identity, mint an authorization code."""
    cfg = _require_config(request)
    form = await request.form()

    def field(name: str) -> str:
        value = form.get(name)
        return value if isinstance(value, str) else ""

    client_id = field("client_id")
    redirect_uri = field("redirect_uri")
    state = field("state") or None

    # Re-validate against the registration rather than trusting the round trip.
    client = db.get_oauth_client(client_id) if client_id else None
    if client is None or not _redirect_ok(redirect_uri, client["redirect_uris"]):
        return _consent_error(400, "This authorization request is no longer valid.")

    if field("action") != "approve":
        return _redirect_error(redirect_uri, "access_denied", state)

    challenge = field("code_challenge")
    scope = _requested_scope(field("scope"))
    if not challenge or scope is None:
        return _consent_error(400, "This authorization request is no longer valid.")

    ns = field("ns").strip()
    inbox_secret = field("inbox_secret").strip()
    identity_id = derive_id(inbox_secret) if inbox_secret else ""
    if not (ns and inbox_secret) or not db.verify_identity_secret(ns, identity_id, inbox_secret):
        instrument.sink.counter("mcp.oauth.consent_rejected")
        return _consent_error(403, "That namespace and inbox secret do not match an identity.")

    code = _new_token()
    db.create_oauth_auth_code(
        code_hash=hash_secret(code),
        client_id=client_id,
        redirect_uri=redirect_uri,
        code_challenge=challenge,
        code_challenge_method="S256",
        scope=scope,
        resource=cfg.resource,
        ns=ns,
        identity_id=identity_id,
        inbox_secret_enc=_seal(inbox_secret, cfg, code_hash=hash_secret(code)),
        expires_at=(_now() + CODE_TTL).isoformat(),
    )
    instrument.sink.counter("mcp.oauth.authorize_granted")
    logger.info(
        "MCP OAuth consent granted: client=%s ns=%s identity=%s", client_id, ns, identity_id
    )
    query = {"code": code}
    if state:
        query["state"] = state
    joiner = "&" if urlparse(redirect_uri).query else "?"
    return RedirectResponse(f"{redirect_uri}{joiner}{urlencode(query)}", status_code=302)


# --- Sealing inbox secrets ---------------------------------------------


def _seal(secret: str, cfg: OAuthConfig, code_hash: str) -> str:
    """Seal an inbox secret with AES-256-GCM, bound to a row identifier.

    A token must be able to act as its identity, and deaddrop stores only the
    hash of an inbox secret — so the secret itself has to survive between
    consent and tool call. It is encrypted rather than stored plainly, and the
    row identifier is the additional authenticated data, so a ciphertext cannot
    be moved to a different code or grant to make one grant act as another
    identity.
    """
    return crypto.encrypt_secret(secret, cfg.key, code_hash).hex()


def _unseal(sealed: str, cfg: OAuthConfig, code_hash: str) -> str:
    return crypto.decrypt_secret(bytes.fromhex(sealed), cfg.key, code_hash)


def _require_config(request: Request) -> OAuthConfig:
    """Fetch the config the routes were registered with."""
    cfg = getattr(request.app.state, STATE_ATTR, None)
    if cfg is None:  # pragma: no cover — routes only exist when config does
        raise RuntimeError("MCP OAuth routes registered without a config")
    return cfg


# --- Token endpoint ----------------------------------------------------


def _token_response(cfg: OAuthConfig, grant_id: str, scope: str) -> JSONResponse:
    """Issue an access token, and a refresh token when offline_access was granted."""
    access = _new_token()
    db.create_oauth_token(
        token_hash=hash_secret(access),
        kind="access",
        grant_id=grant_id,
        expires_at=(_now() + ACCESS_TTL).isoformat(),
    )
    body = {
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": int(ACCESS_TTL.total_seconds()),
        "scope": scope,
    }
    if OFFLINE_SCOPE in scope.split():
        refresh = _new_token()
        db.create_oauth_token(
            token_hash=hash_secret(refresh),
            kind="refresh",
            grant_id=grant_id,
            expires_at=(_now() + REFRESH_TTL).isoformat(),
        )
        body["refresh_token"] = refresh
    return JSONResponse(body, headers={"Cache-Control": "no-store"})


async def handle_token(request: Request) -> Response:
    """The token endpoint. Body is form-urlencoded, per RFC 6749 section 4.1.3."""
    cfg = _require_config(request)
    form = await request.form()

    def field(name: str) -> str:
        value = form.get(name)
        return value if isinstance(value, str) else ""

    grant_type = field("grant_type")
    if grant_type == "authorization_code":
        return _exchange_code(cfg, field)
    if grant_type == "refresh_token":
        return _refresh(cfg, field)
    return _oauth_error(400, "unsupported_grant_type", f"unsupported grant_type: {grant_type!r}")


def _exchange_code(cfg: OAuthConfig, field) -> Response:
    code = field("code")
    if not code:
        return _oauth_error(400, "invalid_request", "code is required")
    code_hash = hash_secret(code)

    # Claiming marks the code consumed under a guard, so a replay loses the race
    # rather than being detected afterwards.
    row = db.claim_oauth_auth_code(code_hash)
    if row is None:
        return _oauth_error(400, "invalid_grant", "authorization code is unknown or already used")
    if _expired(row["expires_at"]):
        return _oauth_error(400, "invalid_grant", "authorization code has expired")
    if field("client_id") and field("client_id") != row["client_id"]:
        return _oauth_error(400, "invalid_grant", "client_id does not match the authorization code")
    if field("redirect_uri") and field("redirect_uri") != row["redirect_uri"]:
        return _oauth_error(
            400, "invalid_grant", "redirect_uri does not match the authorization request"
        )
    if not _resource_ok(field("resource"), cfg):
        return _oauth_error(400, "invalid_target", f"resource must be {cfg.resource}")

    verifier = field("code_verifier")
    if not verifier or not _pkce_matches(verifier, row["code_challenge"]):
        instrument.sink.counter("mcp.oauth.pkce_failed")
        return _oauth_error(400, "invalid_grant", "code_verifier does not match code_challenge")

    grant_id = f"grant_{secrets.token_urlsafe(18)}"
    db.create_oauth_grant(
        grant_id=grant_id,
        client_id=row["client_id"],
        ns=row["ns"],
        identity_id=row["identity_id"],
        inbox_secret_enc=_seal(
            _unseal(row["inbox_secret_enc"], cfg, code_hash), cfg, code_hash=grant_id
        ),
        scope=row["scope"],
        resource=row["resource"],
    )
    instrument.sink.counter("mcp.oauth.token_issued", tags={"grant": "authorization_code"})
    return _token_response(cfg, grant_id, row["scope"])


def _refresh(cfg: OAuthConfig, field) -> Response:
    presented = field("refresh_token")
    if not presented:
        return _oauth_error(400, "invalid_request", "refresh_token is required")
    row = db.get_oauth_token(hash_secret(presented), "refresh")
    if row is None:
        return _oauth_error(400, "invalid_grant", "refresh token is unknown")
    if row["grant_revoked_at"]:
        return _oauth_error(400, "invalid_grant", "grant has been revoked")
    if row["revoked_at"]:
        # A rotated-away refresh token being presented again means either a
        # replay or a client that lost the response. Neither is distinguishable
        # from here, so the whole grant goes — OAuth 2.1 section 4.3.1.
        db.revoke_oauth_grant(row["grant_id"])
        instrument.sink.counter("mcp.oauth.refresh_reuse")
        logger.warning("MCP OAuth refresh token reused; grant %s revoked", row["grant_id"])
        return _oauth_error(400, "invalid_grant", "refresh token has already been used")
    if _expired(row["expires_at"]):
        return _oauth_error(400, "invalid_grant", "refresh token has expired")
    if field("client_id") and field("client_id") != row["client_id"]:
        return _oauth_error(400, "invalid_grant", "client_id does not match the grant")
    if not _resource_ok(field("resource"), cfg):
        return _oauth_error(400, "invalid_target", f"resource must be {cfg.resource}")

    # Rotate: the presented token dies in the same call that mints its successor.
    db.revoke_oauth_token(row["token_hash"])
    instrument.sink.counter("mcp.oauth.token_issued", tags={"grant": "refresh_token"})
    return _token_response(cfg, row["grant_id"], row["scope"])


# --- Resource-server side ----------------------------------------------


@dataclass(frozen=True)
class AccessContext:
    """The identity an accepted access token acts as."""

    ns: str
    identity_id: str
    inbox_secret: str
    scope: str
    client_id: str
    grant_id: str


def verify_access_token(token: str, cfg: OAuthConfig) -> AccessContext | None:
    """Resolve a bearer token to the identity it may act as, or None.

    Audience binding is checked here and not only at issuance: a token whose
    grant recorded a different resource is refused even though this server
    issued it, which is what RFC 8707 audience validation asks a resource
    server to do.
    """
    row = db.get_oauth_token(hash_secret(token), "access")
    if row is None or row["revoked_at"] or row["grant_revoked_at"]:
        return None
    if _expired(row["expires_at"]):
        return None
    if _canonical(row["resource"]) != _canonical(cfg.resource):
        return None
    try:
        inbox_secret = _unseal(row["inbox_secret_enc"], cfg, row["grant_id"])
    except Exception:
        logger.error("MCP OAuth grant %s could not be unsealed", row["grant_id"])
        return None
    return AccessContext(
        ns=row["ns"],
        identity_id=row["identity_id"],
        inbox_secret=inbox_secret,
        scope=row["scope"],
        client_id=row["client_id"],
        grant_id=row["grant_id"],
    )


# --- Registration ------------------------------------------------------

STATE_ATTR = "mcp_oauth_config"


def get_config(app) -> OAuthConfig | None:
    """The config the OAuth routes were registered with, or None."""
    return getattr(app.state, STATE_ATTR, None)


def register(app) -> bool:
    """Mount the authorization-server routes. Returns whether they were mounted.

    Starlette ``Route`` objects rather than FastAPI decorators: every handler
    returns a ``Response`` it has already built, so the response-model and
    validation machinery has nothing to do, and a bare ``Route`` for ``/mcp``
    is already the precedent next door in :mod:`deadrop.mcp_server`.
    """
    cfg = load_config()
    if cfg is None:
        return False
    setattr(app.state, STATE_ATTR, cfg)

    async def prm(request: Request) -> Response:
        return JSONResponse(protected_resource_metadata(_require_config(request)))

    async def asm(request: Request) -> Response:
        return JSONResponse(authorization_server_metadata(_require_config(request)))

    routes = [
        Route("/.well-known/oauth-protected-resource", prm, methods=["GET"], name="mcp_oauth_prm"),
        # The path-inserted form is what a client probes first when a 401
        # carried no resource_metadata pointer.
        Route(
            f"/.well-known/oauth-protected-resource{MCP_PATH}",
            prm,
            methods=["GET"],
            name="mcp_oauth_prm_path",
        ),
        Route(
            "/.well-known/oauth-authorization-server", asm, methods=["GET"], name="mcp_oauth_asm"
        ),
        Route(REGISTER_PATH, handle_register, methods=["POST"], name="mcp_oauth_register"),
        Route(
            AUTHORIZE_PATH,
            handle_authorize_get,
            methods=["GET"],
            name="mcp_oauth_authorize",
        ),
        Route(
            AUTHORIZE_PATH,
            handle_authorize_post,
            methods=["POST"],
            name="mcp_oauth_authorize_submit",
        ),
        Route(TOKEN_PATH, handle_token, methods=["POST"], name="mcp_oauth_token"),
    ]
    app.router.routes.extend(routes)
    return True
