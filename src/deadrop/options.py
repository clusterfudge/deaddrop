"""Configuration options for the Deaddrop client.

Provides DeaddropOptions for configuring backend selection and connection details.
Supports environment variable overrides for CI/CD and containerized deployments.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class DeaddropConfigError(Exception):
    """Raised when DeaddropOptions configuration is invalid."""

    pass


@dataclass
class DeaddropOptions:
    """Configuration options for the Deaddrop client.

    Supports three modes (mutually exclusive):
    1. Local: File-based storage in a .deaddrop directory
    2. Remote: HTTP API connection to a deaddrop server
    3. In-memory: Ephemeral SQLite for testing

    Environment Variables:
        DEADDROP_PATH: Force local backend with specific path
        DEADDROP_URL: Force remote backend with specific URL
        DEADDROP_BEARER_TOKEN: Bearer token for remote admin operations

    Examples:
        # Auto-discover (default)
        options = DeaddropOptions()

        # Explicit local
        options = DeaddropOptions(local=True)
        options = DeaddropOptions(path=".deaddrop")

        # Remote
        options = DeaddropOptions(url="https://deaddrop.example.com")

        # In-memory for tests
        options = DeaddropOptions(in_memory=True)
    """

    # Local backend options
    path: str | Path | None = None
    """Explicit path to .deaddrop directory. Implies local mode."""

    local: bool = False
    """Auto-discover local .deaddrop (CWD or git root). Implies local mode."""

    in_memory: bool = False
    """Use ephemeral in-memory SQLite. Perfect for testing."""

    # Remote backend options
    url: str | None = None
    """Remote deaddrop server URL."""

    bearer_token: str | None = None
    """Bearer token for admin operations on remote server."""

    # Behavior options
    create_if_missing: bool = False
    """If True, initialize .deaddrop directory if not found (local mode only)."""

    # Internal: resolved values after environment processing
    _resolved_path: Path | None = field(default=None, repr=False)
    _resolved_url: str | None = field(default=None, repr=False)
    _backend_type: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        """Validate options and apply environment variable overrides."""
        self._apply_env_overrides()
        self._validate()
        self._resolve_backend()

    def _apply_env_overrides(self) -> None:
        """Apply environment variable overrides.

        Environment variables only apply when no explicit backend is specified.
        Explicit options (path, local, in_memory, url) take priority.
        """
        # Check if any explicit backend option was provided
        has_explicit = self.path is not None or self.local or self.in_memory or self.url is not None

        if has_explicit:
            # Only load bearer token from env, don't override backend
            if not self.bearer_token:
                self.bearer_token = os.environ.get("DEADDROP_BEARER_TOKEN")
            return

        # No explicit options - check environment variables
        env_path = os.environ.get("DEADDROP_PATH")
        if env_path:
            self.path = env_path

        env_url = os.environ.get("DEADDROP_URL")
        if env_url:
            self.url = env_url

        if not self.bearer_token:
            self.bearer_token = os.environ.get("DEADDROP_BEARER_TOKEN")

    def _validate(self) -> None:
        """Validate that options are consistent."""
        local_opts = [self.path is not None, self.local, self.in_memory]
        remote_opts = [self.url is not None]

        local_count = sum(local_opts)
        remote_count = sum(remote_opts)

        # Check mutual exclusivity
        if local_count > 0 and remote_count > 0:
            raise DeaddropConfigError(
                "Cannot mix local options (path, local, in_memory) with remote options (url). "
                "Choose one backend type."
            )

        # in_memory is exclusive even among local options
        if self.in_memory and (self.path is not None or self.local):
            raise DeaddropConfigError("in_memory cannot be combined with path or local options.")

        # create_if_missing only makes sense for local
        if self.create_if_missing and self.url:
            raise DeaddropConfigError(
                "create_if_missing only applies to local backends, not remote."
            )

    def _resolve_backend(self) -> None:
        """Determine the backend type and resolve paths/URLs."""
        if self.in_memory:
            self._backend_type = "in_memory"
            return

        if self.path is not None:
            self._backend_type = "local"
            self._resolved_path = Path(self.path).resolve()
            return

        if self.local:
            self._backend_type = "local"
            # Path will be resolved during discovery
            return

        if self.url is not None:
            self._backend_type = "remote"
            self._resolved_url = self.url.rstrip("/")
            return

        # No explicit options - will use auto-discovery
        self._backend_type = None

    @property
    def backend_type(self) -> str | None:
        """The resolved backend type: 'local', 'remote', 'in_memory', or None (auto-discover)."""
        return self._backend_type

    @property
    def resolved_path(self) -> Path | None:
        """The resolved .deaddrop path (for local backends)."""
        return self._resolved_path

    @property
    def resolved_url(self) -> str | None:
        """The resolved server URL (for remote backends)."""
        return self._resolved_url

    def is_auto_discover(self) -> bool:
        """True if no explicit backend was specified (will auto-discover)."""
        return self._backend_type is None

    def is_local(self) -> bool:
        """True if configured for local backend."""
        return self._backend_type == "local"

    def is_remote(self) -> bool:
        """True if configured for remote backend."""
        return self._backend_type == "remote"

    def is_in_memory(self) -> bool:
        """True if configured for in-memory backend."""
        return self._backend_type == "in_memory"

    @classmethod
    def for_local(
        cls,
        path: str | Path | None = None,
        create_if_missing: bool = False,
    ) -> "DeaddropOptions":
        """Create options for local backend.

        Args:
            path: Explicit .deaddrop path. If None, auto-discovers.
            create_if_missing: Initialize .deaddrop if not found.
        """
        if path:
            return cls(path=path, create_if_missing=create_if_missing)
        return cls(local=True, create_if_missing=create_if_missing)

    @classmethod
    def for_remote(
        cls,
        url: str,
        bearer_token: str | None = None,
    ) -> "DeaddropOptions":
        """Create options for remote backend.

        Args:
            url: Deaddrop server URL.
            bearer_token: Bearer token for admin operations.
        """
        return cls(url=url, bearer_token=bearer_token)

    @classmethod
    def for_in_memory(cls) -> "DeaddropOptions":
        """Create options for in-memory backend (testing)."""
        return cls(in_memory=True)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary (for debugging/logging)."""
        return {
            "backend_type": self._backend_type,
            "path": str(self._resolved_path) if self._resolved_path else None,
            "url": self._resolved_url,
            "local": self.local,
            "in_memory": self.in_memory,
            "create_if_missing": self.create_if_missing,
            "has_bearer_token": self.bearer_token is not None,
        }
