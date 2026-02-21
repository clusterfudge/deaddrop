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
    ) -> list[dict[str, Any]]:
        """Get messages for an identity.

        Args:
            ns: Namespace ID.
            identity_id: Identity ID.
            secret: Inbox secret.
            unread_only: Only return unread messages.
            after_mid: Cursor for pagination.
            mark_as_read: Whether to mark messages as read.

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

    # --- Room Operations ---

    def create_room(
        self,
        ns: str,
        creator_secret: str,
        display_name: str | None = None,
    ) -> dict[str, Any]:
        """Create a new room in a namespace.

        The creator automatically becomes the first member.

        Args:
            ns: Namespace ID.
            creator_secret: Creator's inbox secret.
            display_name: Optional display name for the room.

        Returns:
            dict with: room_id, ns, display_name, created_by, created_at
        """
        return self._backend.create_room(ns, creator_secret, display_name)

    def list_rooms(
        self,
        ns: str,
        secret: str,
    ) -> list[dict[str, Any]]:
        """List rooms the caller is a member of.

        Args:
            ns: Namespace ID.
            secret: Caller's inbox secret.

        Returns:
            List of room dicts with membership info.
        """
        return self._backend.list_rooms(ns, secret)

    def get_room(
        self,
        ns: str,
        room_id: str,
        secret: str,
    ) -> dict[str, Any] | None:
        """Get room details. Requires membership.

        Args:
            ns: Namespace ID.
            room_id: Room ID.
            secret: Caller's inbox secret.

        Returns:
            Room dict or None if not found/not a member.
        """
        return self._backend.get_room(ns, room_id, secret)

    def delete_room(
        self,
        ns: str,
        room_id: str,
        ns_secret: str,
    ) -> bool:
        """Delete a room. Requires namespace owner.

        Args:
            ns: Namespace ID.
            room_id: Room ID.
            ns_secret: Namespace secret.

        Returns:
            True if deleted.
        """
        return self._backend.delete_room(ns, room_id, ns_secret)

    def add_room_member(
        self,
        ns: str,
        room_id: str,
        identity_id: str,
        secret: str,
    ) -> dict[str, Any]:
        """Add a member to a room.

        Any room member can add other identities from the same namespace.

        Args:
            ns: Namespace ID.
            room_id: Room ID.
            identity_id: Identity to add.
            secret: Caller's inbox secret (must be a member).

        Returns:
            Member info dict.
        """
        return self._backend.add_room_member(ns, room_id, identity_id, secret)

    def remove_room_member(
        self,
        ns: str,
        room_id: str,
        identity_id: str,
        secret: str,
    ) -> bool:
        """Remove a member from a room (or leave).

        Members can remove themselves or be removed by other members.

        Args:
            ns: Namespace ID.
            room_id: Room ID.
            identity_id: Identity to remove.
            secret: Caller's inbox secret.

        Returns:
            True if removed.
        """
        return self._backend.remove_room_member(ns, room_id, identity_id, secret)

    def list_room_members(
        self,
        ns: str,
        room_id: str,
        secret: str,
    ) -> list[dict[str, Any]]:
        """List members of a room.

        Args:
            ns: Namespace ID.
            room_id: Room ID.
            secret: Caller's inbox secret (must be a member).

        Returns:
            List of member info dicts.
        """
        return self._backend.list_room_members(ns, room_id, secret)

    def send_room_message(
        self,
        ns: str,
        room_id: str,
        secret: str,
        body: str,
        content_type: str = "text/plain",
        reference_mid: str | None = None,
    ) -> dict[str, Any]:
        """Send a message to a room.

        Args:
            ns: Namespace ID.
            room_id: Room ID.
            secret: Sender's inbox secret (must be a member).
            body: Message body.
            content_type: MIME type.
            reference_mid: Optional message ID to reply to (creates a thread reply).

        Returns:
            Message dict.
        """
        return self._backend.send_room_message(
            ns,
            room_id,
            secret,
            body,
            content_type,
            reference_mid=reference_mid,
        )

    def get_room_messages(
        self,
        ns: str,
        room_id: str,
        secret: str,
        after_mid: str | None = None,
        limit: int = 100,
        include_replies: bool = True,
    ) -> list[dict[str, Any]]:
        """Get messages from a room.

        Args:
            ns: Namespace ID.
            room_id: Room ID.
            secret: Caller's inbox secret (must be a member).
            after_mid: Only get messages after this ID.
            limit: Maximum messages to return.
            include_replies: If False, exclude thread replies and include
                thread metadata (reply_count, last_reply_at) on root messages.

        Returns:
            List of message dicts.
        """
        return self._backend.get_room_messages(
            ns,
            room_id,
            secret,
            after_mid=after_mid,
            limit=limit,
            include_replies=include_replies,
        )

    def get_thread(
        self,
        ns: str,
        room_id: str,
        secret: str,
        root_mid: str,
    ) -> dict[str, Any] | None:
        """Get a thread: root message and all replies.

        Args:
            ns: Namespace ID.
            room_id: Room ID.
            secret: Caller's inbox secret (must be a member).
            root_mid: Message ID of the thread root.

        Returns:
            Dict with "root", "replies", "reply_count", or None if not found.
        """
        return self._backend.get_thread(ns, room_id, secret, root_mid)

    def update_room_read_cursor(
        self,
        ns: str,
        room_id: str,
        secret: str,
        last_read_mid: str,
    ) -> bool:
        """Update read cursor for the caller.

        Args:
            ns: Namespace ID.
            room_id: Room ID.
            secret: Caller's inbox secret.
            last_read_mid: Message ID of last read message.

        Returns:
            True if updated.
        """
        return self._backend.update_room_read_cursor(ns, room_id, secret, last_read_mid)

    def get_room_unread_count(
        self,
        ns: str,
        room_id: str,
        secret: str,
    ) -> int:
        """Get unread message count for the caller.

        Args:
            ns: Namespace ID.
            room_id: Room ID.
            secret: Caller's inbox secret.

        Returns:
            Number of unread messages.
        """
        return self._backend.get_room_unread_count(ns, room_id, secret)

    # wait_for_room_messages removed — use subscribe() for real-time updates

    # listen_room removed — use subscribe() for real-time updates

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

    # wait_for_messages removed — use subscribe() for real-time updates

    # listen removed — use subscribe() for real-time updates

    # --- Subscription Methods ---

    def subscribe(
        self,
        ns: str,
        secret: str,
        topics: dict[str, str | None],
        timeout: int = 30,
    ) -> dict[str, Any]:
        """Subscribe to topic changes (poll mode).

        Blocks until any subscribed topic has new messages, or timeout.

        Args:
            ns: Namespace ID.
            secret: Caller's inbox secret.
            topics: Map of topic_key -> last_seen_mid (None = never seen).
                Topic keys: "inbox:{identity_id}" or "room:{room_id}"
            timeout: Max seconds to wait (1-60).

        Returns:
            dict with:
                events: Map of changed topic_key -> latest_mid
                timeout: True if no events before timeout

        Example:
            result = client.subscribe(ns, secret, {
                f"inbox:{my_id}": last_inbox_mid,
                f"room:{room_id}": last_room_mid,
            })
            for topic, mid in result["events"].items():
                print(f"New activity on {topic}")
        """
        return self._backend.subscribe(ns, secret, topics, timeout)

    def subscribe_stream(
        self,
        ns: str,
        secret: str,
        topics: dict[str, str | None],
    ):
        """Subscribe to topic changes (streaming mode).

        Returns an iterator that yields event dicts as they occur.

        Args:
            ns: Namespace ID.
            secret: Caller's inbox secret.
            topics: Map of topic_key -> last_seen_mid (None = never seen).

        Yields:
            dicts with 'topic' and 'latest_mid' keys.

        Example:
            for event in client.subscribe_stream(ns, secret, topics):
                print(f"Change on {event['topic']}: {event['latest_mid']}")
        """
        yield from self._backend.subscribe_stream(ns, secret, topics)

    def listen_all(
        self,
        ns: str,
        secret: str,
        topics: dict[str, str | None],
        timeout: int = 30,
    ):
        """Generator that yields topic change events across multiple topics.

        Uses poll-mode subscribe in a loop, yielding (topic, latest_mid) tuples.
        Automatically updates cursors to avoid re-reporting the same change.

        This is the recommended way to monitor multiple topics (inbox + rooms)
        simultaneously.

        Args:
            ns: Namespace ID.
            secret: Caller's inbox secret.
            topics: Map of topic_key -> last_seen_mid (None = never seen).
            timeout: Long-poll timeout per iteration (1-60 seconds).

        Yields:
            Tuples of (topic_key, latest_mid).

        Example:
            topics = {
                f"inbox:{my_id}": None,
                f"room:{room1_id}": None,
                f"room:{room2_id}": None,
            }
            for topic, mid in client.listen_all(ns, secret, topics):
                print(f"New activity on {topic} (latest: {mid})")
                if topic.startswith("inbox:"):
                    messages = client.get_inbox(ns, my_id, secret, after_mid=mid)
                elif topic.startswith("room:"):
                    room_id = topic.split(":", 1)[1]
                    messages = client.get_room_messages(ns, room_id, secret, after_mid=mid)
        """
        cursors = dict(topics)

        while True:
            result = self.subscribe(ns, secret, cursors, timeout)

            for topic, mid in result.get("events", {}).items():
                cursors[topic] = mid
                yield topic, mid

    # --- Context Manager ---

    def close(self) -> None:
        """Close backend resources."""
        self._backend.close()

    def __enter__(self) -> "Deaddrop":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    # --- Invite Methods ---

    def create_invite(
        self,
        ns: str,
        identity_id: str,
        identity_secret: str,
        ns_secret: str,
        display_name: str | None = None,
        expires_at: str | None = None,
    ) -> dict[str, Any]:
        """Create an invite for an identity.

        The invite URL can be shared to allow claiming the identity's credentials.
        The URL contains an encryption key in the fragment that never leaves the client.

        Args:
            ns: Namespace ID
            identity_id: Identity to create invite for
            identity_secret: The identity's secret (to be encrypted in the invite)
            ns_secret: Namespace secret (for authorization)
            display_name: Optional display name for the invite
            expires_at: Optional expiration time (ISO 8601)

        Returns:
            dict with:
                invite_id: The invite identifier
                invite_url: Full URL to share (includes encryption key in fragment)
                expires_at: When the invite expires (if set)

        Example:
            # Create an invite for Bob
            invite = client.create_invite(ns, bob["id"], bob["secret"], ns_secret)
            print(f"Share this link: {invite['invite_url']}")
        """
        return self._backend.create_invite(
            ns=ns,
            identity_id=identity_id,
            identity_secret=identity_secret,
            ns_secret=ns_secret,
            display_name=display_name,
            expires_at=expires_at,
        )

    def claim_invite(
        self,
        invite_url: str,
    ) -> dict[str, Any]:
        """Claim an invite and get the identity credentials.

        The invite URL contains the server, invite ID, and encryption key.
        After claiming, the invite cannot be used again.

        Args:
            invite_url: Full invite URL (e.g., https://server/join/{id}#{key})

        Returns:
            dict with:
                ns: Namespace ID
                identity_id: Identity ID
                secret: Identity secret (decrypted)
                display_name: Identity display name (if set)

        Example:
            # Claim an invite URL
            creds = client.claim_invite("https://deaddrop.example.com/join/abc123#key")
            print(f"Got credentials for identity {creds['identity_id']}")
        """
        return self._backend.claim_invite(invite_url=invite_url)
