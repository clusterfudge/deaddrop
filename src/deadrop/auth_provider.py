"""Pluggable authentication system for deadrop.

Auth providers can be configured via environment variables:
- DEADROP_AUTH_MODULE: Python module path for custom auth (e.g., 'myapp.auth')
- HEARE_AUTH_URL: If set, uses built-in heare-auth integration

Custom auth modules must expose:
- verify_bearer_token(token: str) -> AuthResult
- is_enabled() -> bool
- extract_bearer_token(authorization: str | None) -> str | None (optional)

The AuthResult dataclass is provided by this module for custom implementations.
"""

import importlib
import os
from dataclasses import dataclass


@dataclass
class AuthResult:
    """Result of an authentication attempt."""

    valid: bool
    key_id: str | None = None
    name: str | None = None
    metadata: dict | None = None
    error: str | None = None


def _get_auth_module():
    """Get the configured auth module, or None if not configured."""
    # Check for custom auth module first
    custom_module = os.environ.get("DEADROP_AUTH_MODULE")
    if custom_module:
        try:
            return importlib.import_module(custom_module)
        except ImportError as e:
            raise ImportError(f"Failed to import auth module '{custom_module}': {e}") from e

    # Check for built-in heare-auth
    if os.environ.get("HEARE_AUTH_URL"):
        from . import heare_auth

        return heare_auth

    return None


def is_auth_enabled() -> bool:
    """Check if any authentication is configured."""
    module = _get_auth_module()
    if module is None:
        return False

    # Check if module has is_enabled, otherwise assume enabled if loaded
    if hasattr(module, "is_enabled"):
        return module.is_enabled()
    elif hasattr(module, "is_heare_auth_enabled"):
        # Backwards compat with heare_auth module
        return module.is_heare_auth_enabled()

    return True


def verify_bearer_token(token: str) -> AuthResult:
    """
    Verify a bearer token using the configured auth module.

    Args:
        token: The bearer token to verify

    Returns:
        AuthResult with validation status and metadata
    """
    module = _get_auth_module()
    if module is None:
        return AuthResult(valid=False, error="No auth module configured")

    return module.verify_bearer_token(token)


def extract_bearer_token(authorization: str | None) -> str | None:
    """
    Extract bearer token from Authorization header.

    Uses custom module's implementation if available, otherwise default.

    Args:
        authorization: The full Authorization header value

    Returns:
        The token if valid Bearer format, None otherwise
    """
    module = _get_auth_module()
    if module and hasattr(module, "extract_bearer_token"):
        return module.extract_bearer_token(authorization)

    # Default implementation
    if not authorization:
        return None

    parts = authorization.split(" ", 1)
    if len(parts) != 2:
        return None

    scheme, token = parts
    if scheme.lower() != "bearer":
        return None

    return token.strip()


def get_auth_method_name() -> str:
    """Get the name of the current auth method for logging/debugging."""
    custom_module = os.environ.get("DEADROP_AUTH_MODULE")
    if custom_module:
        return f"custom:{custom_module}"

    if os.environ.get("HEARE_AUTH_URL"):
        return "heare-auth"

    return "none"
