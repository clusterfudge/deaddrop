"""Unified Deaddrop client with backend abstraction.

This module provides the main `Deaddrop` class that users interact with.
The backend (local SQLite, remote HTTP, or in-memory) is abstracted away
behind a unified interface.

Usage:
    # Auto-discover backend
    client = Deaddrop()

    # Explicit backends
    client = Deaddrop.local()
    client = Deaddrop.remote(url="https://deaddrop.example.com")
    client = Deaddrop.in_memory()

    # Create new local .deaddrop
    client = Deaddrop.create_local()

    # With explicit options
    client = Deaddrop(DeaddropOptions(path=".deaddrop"))
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .backends import Backend, InMemoryBackend, LocalBackend, RemoteBackend
from .discovery import DeaddropNotFound, discover_backend, get_deaddrop_init_path
from .options import DeaddropOptions


class Deaddrop:
    """Unified client for deaddrop operations.

    Provides a consistent interface regardless of whether the backend
    is a local .deaddrop directory, a remote server, or in-memory.

    Examples:
        # Auto-discover existing configuration
        client = Deaddrop()

        # Explicit local backend
        client = Deaddrop.local()

        # Create new local .deaddrop
        client = Deaddrop.create_local()

        # Remote server
        client = Deaddrop.remote(url="https://deaddrop.example.com")

        # In-memory for testing
        client = Deaddrop.in_memory()
    """

    def __init__(self, options: DeaddropOptions | None = None):
        """Initialize Deaddrop client.

        Args:
            options: Configuration options. If None, auto-discovers backend.
        """
        self._options = options or DeaddropOptions()
        self._backend = self._create_backend()

    def _create_backend(self) -> Backend:
        """Create the appropriate backend based on options."""
        opts = self._options

        # Explicit in-memory
        if opts.is_in_memory():
            return InMemoryBackend()

        # Explicit local with path
        if opts.resolved_path is not None:
            return LocalBackend(
                opts.resolved_path,
                create_if_missing=opts.create_if_missing,
            )

        # Explicit remote
        if opts.is_remote():
            assert opts.resolved_url is not None
            return RemoteBackend(
                url=opts.resolved_url,
                bearer_token=opts.bearer_token,
            )

        # Auto-discover local (local=True but no path)
        if opts.local:
            result = discover_backend(require_local=True)
            assert result.path is not None
            return LocalBackend(result.path)

        # Full auto-discovery
        if opts.is_auto_discover():
            result = discover_backend()
            if result.backend_type == "local":
                assert result.path is not None
                return LocalBackend(result.path)
            elif result.backend_type == "remote":
                assert result.url is not None
                return RemoteBackend(
                    url=result.url,
                    bearer_token=result.bearer_token,
                )

        raise DeaddropNotFound("Unable to determine backend from options")

    # --- Factory Methods ---

    @classmethod
    def discover(cls) -> "Deaddrop":
        """Create client by discovering existing configuration.

        Same as `Deaddrop()` - provided for explicitness.
        """
        return cls()

    @classmethod
    def local(cls, path: str | Path | None = None) -> "Deaddrop":
        """Create client with local backend.

        Args:
            path: Path to .deaddrop directory. If None, auto-discovers.

        Raises:
            DeaddropNotFound: If no local .deaddrop found.
        """
        if path:
            return cls(DeaddropOptions(path=path))
        return cls(DeaddropOptions(local=True))

    @classmethod
    def remote(
        cls,
        url: str,
        bearer_token: str | None = None,
    ) -> "Deaddrop":
        """Create client with remote backend.

        Args:
            url: Deaddrop server URL.
            bearer_token: Bearer token for admin operations.
        """
        return cls(DeaddropOptions(url=url, bearer_token=bearer_token))

    @classmethod
    def in_memory(cls) -> "Deaddrop":
        """Create client with ephemeral in-memory backend.

        Perfect for testing - no cleanup needed.
        """
        return cls(DeaddropOptions(in_memory=True))

    @classmethod
    def create_local(
        cls,
        path: str | Path | None = None,
        add_to_gitignore: bool = True,
    ) -> "Deaddrop":
        """Create a new local .deaddrop directory.

        Args:
            path: Where to create .deaddrop. If None, uses git root or cwd.
            add_to_gitignore: Add .deaddrop/ to .gitignore if in git repo.

        Returns:
            Client connected to the new local backend.
        """
        if path is None:
            path = get_deaddrop_init_path()
        else:
            path = Path(path)

        backend = LocalBackend.create(path=path, add_to_gitignore=add_to_gitignore)
        client = cls.__new__(cls)
        client._options = DeaddropOptions(path=path)
        client._backend = backend
        return client

    # --- Properties ---

    @property
    def backend(self) -> str:
        """Backend type: 'local', 'remote', or 'in_memory'."""
        return self._backend.get_info().backend_type

    @property
    def location(self) -> str:
        """Backend location: path, URL, or ':memory:'."""
        return self._backend.get_info().location

    # --- Namespace Operations ---

    def create_namespace(
        self,
        display_name: str | None = None,
        ttl_hours: int = 24,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create a new namespace.

        Args:
            display_name: Human-readable name.
            ttl_hours: Message TTL after reading (0 = no expiry).
            metadata: Additional metadata.

        Returns:
            dict with: ns, secret, slug, metadata, ttl_hours
        """
        return self._backend.create_namespace(
            display_name=display_name,
            ttl_hours=ttl_hours,
            metadata=metadata,
        )

    def list_namespaces(self) -> list[dict[str, Any]]:
        """List all namespaces."""
        return self._backend.list_namespaces()

    def get_namespace(self, ns: str) -> dict[str, Any] | None:
        """Get namespace by ID."""
        return self._backend.get_namespace(ns)

    def delete_namespace(self, ns: str) -> bool:
        """Delete a namespace and all its data."""
        return self._backend.delete_namespace(ns)

    def archive_namespace(self, ns: str, secret: str) -> bool:
        """Archive a namespace (soft delete)."""
        return self._backend.archive_namespace(ns, secret)

    # --- Identity Operations ---

    def create_identity(
        self,
        ns: str,
        display_name: str | None = None,
        metadata: dict[str, Any] | None = None,
        ns_secret: str | None = None,
    ) -> dict[str, Any]:
        """Create a new identity in a namespace.

        Args:
            ns: Namespace ID.
            display_name: Human-readable name.
            metadata: Additional metadata.
            ns_secret: Namespace secret (required for remote backend).

        Returns:
            dict with: id, secret, metadata
        """
        return self._backend.create_identity(
            ns=ns,
            display_name=display_name,
            metadata=metadata,
            ns_secret=ns_secret,
        )

    def list_identities(
        self,
        ns: str,
        secret: str | None = None,
    ) -> list[dict[str, Any]]:
        """List identities in a namespace.

        Args:
            ns: Namespace ID.
            secret: Namespace secret or inbox secret for authentication.
        """
        return self._backend.list_identities(ns, secret)

    def get_identity(self, ns: str, identity_id: str) -> dict[str, Any] | None:
        """Get identity by ID."""
        return self._backend.get_identity(ns, identity_id)

    def delete_identity(
        self,
        ns: str,
        identity_id: str,
        ns_secret: str | None = None,
    ) -> bool:
        """Delete an identity."""
        return self._backend.delete_identity(ns, identity_id, ns_secret)

    # --- Message Operations ---

    def send_message(
        self,
        ns: str,
        from_secret: str,
        to_id: str,
        body: str,
        content_type: str = "text/plain",
        ttl_hours: int | None = None,
    ) -> dict[str, Any]:
        """Send a message.

        Args:
            ns: Namespace ID.
            from_secret: Sender's inbox secret.
            to_id: Recipient identity ID.
            body: Message body.
            content_type: MIME type (default: text/plain).
            ttl_hours: Optional TTL for ephemeral messages.

        Returns:
            dict with: mid, from, to, content_type, created_at
        """
        return self._backend.send_message(
            ns=ns,
            from_secret=from_secret,
            to_id=to_id,
            body=body,
            content_type=content_type,
            ttl_hours=ttl_hours,
        )

    def get_inbox(
        self,
        ns: str,
        identity_id: str,
        secret: str,
        unread_only: bool = False,
        after_mid: str | None = None,
        mark_as_read: bool = True,
        wait: int = 0,
    ) -> list[dict[str, Any]]:
        """Get messages for an identity.

        Args:
            ns: Namespace ID.
            identity_id: Identity ID.
            secret: Inbox secret.
            unread_only: Only return unread messages.
            after_mid: Cursor for pagination.
            mark_as_read: Whether to mark messages as read.
            wait: Long-poll timeout in seconds (0-60). If no messages,
                  wait up to this many seconds for new messages.

        Returns:
            List of messages.
        """
        return self._backend.get_inbox(
            ns=ns,
            identity_id=identity_id,
            secret=secret,
            unread_only=unread_only,
            after_mid=after_mid,
            mark_as_read=mark_as_read,
            wait=wait,
        )

    def delete_message(
        self,
        ns: str,
        identity_id: str,
        secret: str,
        mid: str,
    ) -> bool:
        """Delete a message."""
        return self._backend.delete_message(ns, identity_id, secret, mid)

    def archive_message(
        self,
        ns: str,
        identity_id: str,
        secret: str,
        mid: str,
    ) -> bool:
        """Archive a message."""
        return self._backend.archive_message(ns, identity_id, secret, mid)

    def get_archived_messages(
        self,
        ns: str,
        identity_id: str,
        secret: str,
    ) -> list[dict[str, Any]]:
        """Get archived messages."""
        return self._backend.get_archived_messages(ns, identity_id, secret)

    # --- Convenience Methods ---

    def quick_setup(
        self,
        namespace_name: str,
        identities: list[str],
    ) -> dict[str, Any]:
        """Quick setup: create namespace and identities in one call.

        Perfect for testing scenarios.

        Args:
            namespace_name: Display name for the namespace.
            identities: List of identity display names.

        Returns:
            dict with:
                namespace: {ns, secret, ...}
                identities: {name: {id, secret}, ...}

        Example:
            setup = client.quick_setup("Test", ["Alice", "Bob"])
            alice = setup["identities"]["Alice"]
            bob = setup["identities"]["Bob"]
            client.send_message(setup["namespace"]["ns"], alice["secret"], bob["id"], "Hi!")
        """
        ns = self.create_namespace(display_name=namespace_name)

        identity_map = {}
        for name in identities:
            identity = self.create_identity(
                ns["ns"],
                display_name=name,
                ns_secret=ns.get("secret"),
            )
            identity_map[name] = identity

        return {
            "namespace": ns,
            "identities": identity_map,
        }

    def send_and_receive(
        self,
        ns: str,
        from_identity: dict[str, Any],
        to_identity: dict[str, Any],
        body: str,
        content_type: str = "text/plain",
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Send a message and immediately receive it.

        Convenience method for testing message flow.

        Args:
            ns: Namespace ID.
            from_identity: Sender identity dict (must have 'secret').
            to_identity: Recipient identity dict (must have 'id' and 'secret').
            body: Message body.
            content_type: MIME type.

        Returns:
            Tuple of (sent_message, received_message).
        """
        sent = self.send_message(
            ns=ns,
            from_secret=from_identity["secret"],
            to_id=to_identity["id"],
            body=body,
            content_type=content_type,
        )

        messages = self.get_inbox(
            ns=ns,
            identity_id=to_identity["id"],
            secret=to_identity["secret"],
        )

        received = next((m for m in messages if m["mid"] == sent["mid"]), None)
        if not received:
            raise RuntimeError("Message not found in inbox")

        return sent, received

    # --- Long-Polling Convenience Methods ---

    def wait_for_messages(
        self,
        ns: str,
        identity_id: str,
        secret: str,
        timeout: int = 30,
        unread_only: bool = False,
        after_mid: str | None = None,
    ) -> list[dict[str, Any]]:
        """Wait for new messages with long-polling.

        Convenience wrapper around get_inbox with wait parameter.

        Args:
            ns: Namespace ID.
            identity_id: Identity ID.
            secret: Inbox secret.
            timeout: How long to wait for messages (1-60 seconds).
            unread_only: Only return unread messages.
            after_mid: Only return messages after this ID.

        Returns:
            List of messages (may be empty if timeout reached).

        Example:
            # Wait up to 30 seconds for new messages
            messages = client.wait_for_messages(ns, bob["id"], bob["secret"])

            # Wait for unread messages only
            messages = client.wait_for_messages(ns, bob["id"], bob["secret"], unread_only=True)

            # Wait for messages after a specific ID (useful for streaming)
            last_mid = messages[-1]["mid"] if messages else None
            new_messages = client.wait_for_messages(ns, bob["id"], bob["secret"], after_mid=last_mid)
        """
        return self.get_inbox(
            ns=ns,
            identity_id=identity_id,
            secret=secret,
            unread_only=unread_only,
            after_mid=after_mid,
            wait=max(1, min(timeout, 60)),
        )

    def listen(
        self,
        ns: str,
        identity_id: str,
        secret: str,
        timeout: int = 30,
        unread_only: bool = False,
    ):
        """Generator that yields messages as they arrive.

        Uses long-polling to efficiently wait for new messages.
        Yields messages one at a time as they arrive.

        Args:
            ns: Namespace ID.
            identity_id: Identity ID.
            secret: Inbox secret.
            timeout: Long-poll timeout per iteration (1-60 seconds).
            unread_only: Only yield unread messages.

        Yields:
            Messages as they arrive.

        Example:
            for message in client.listen(ns, bob["id"], bob["secret"]):
                print(f"Got message: {message['body']}")
                if message["body"] == "quit":
                    break
        """
        last_mid: str | None = None

        while True:
            messages = self.wait_for_messages(
                ns=ns,
                identity_id=identity_id,
                secret=secret,
                timeout=timeout,
                unread_only=unread_only,
                after_mid=last_mid,
            )

            for msg in messages:
                last_mid = msg["mid"]
                yield msg

    # --- Context Manager ---

    def close(self) -> None:
        """Close backend resources."""
        self._backend.close()

    def __enter__(self) -> "Deaddrop":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
