"""Integration with heare-auth for API key verification."""

import os
from dataclasses import dataclass

import httpx


@dataclass
class AuthResult:
    """Result of an authentication attempt."""

    valid: bool
    key_id: str | None = None
    name: str | None = None
    metadata: dict | None = None
    error: str | None = None


def get_auth_url() -> str | None:
    """Get heare-auth service URL from environment."""
    return os.environ.get("HEARE_AUTH_URL")


def is_heare_auth_enabled() -> bool:
    """Check if heare-auth is configured."""
    return bool(get_auth_url())


def verify_bearer_token(token: str) -> AuthResult:
    """
    Verify a bearer token against heare-auth service.

    Args:
        token: The bearer token (API key) to verify

    Returns:
        AuthResult with validation status and metadata
    """
    auth_url = get_auth_url()
    if not auth_url:
        return AuthResult(valid=False, error="HEARE_AUTH_URL not configured")

    try:
        response = httpx.post(
            f"{auth_url}/verify",
            json={"api_key": token},
            timeout=5.0,
        )

        if response.status_code == 200:
            data = response.json()
            return AuthResult(
                valid=data.get("valid", False),
                key_id=data.get("key_id"),
                name=data.get("name"),
                metadata=data.get("metadata", {}),
                error=data.get("error"),
            )
        else:
            return AuthResult(
                valid=False,
                error=f"Auth service returned {response.status_code}",
            )
    except httpx.RequestError as e:
        return AuthResult(valid=False, error=f"Auth service unavailable: {e}")


def extract_bearer_token(authorization: str | None) -> str | None:
    """
    Extract bearer token from Authorization header.

    Args:
        authorization: The full Authorization header value

    Returns:
        The token if valid Bearer format, None otherwise
    """
    if not authorization:
        return None

    parts = authorization.split(" ", 1)
    if len(parts) != 2:
        return None

    scheme, token = parts
    if scheme.lower() != "bearer":
        return None

    return token.strip()
