"""Backend implementations for the Deaddrop client.

This module provides backend classes that abstract the underlying storage/API:
- Backend: Abstract base class defining the interface
- LocalBackend: File-system based SQLite storage
- RemoteBackend: HTTP API client
- InMemoryBackend: Ephemeral SQLite for testing
"""

from __future__ import annotations

import sqlite3
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from . import db
from .auth import derive_id
from .discovery import ensure_gitignore, get_deaddrop_init_path


@dataclass
class BackendInfo:
    """Information about a backend instance."""

    backend_type: str
    """Type of backend: 'local', 'remote', or 'in_memory'."""

    location: str
    """Location description: path, URL, or ':memory:'."""


class Backend(ABC):
    """Abstract base class for deaddrop backends.

    All backends implement the same interface for namespace, identity,
    and message operations. This allows the Deaddrop client to work
    identically with local, remote, or in-memory storage.
    """

    @abstractmethod
    def get_info(self) -> BackendInfo:
        """Get information about this backend."""
        ...

    # --- Namespace Operations ---

    @abstractmethod
    def create_namespace(
        self,
        display_name: str | None = None,
        ttl_hours: int = 24,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create a new namespace.

        Returns:
            dict with keys: ns, secret, slug, metadata, ttl_hours
        """
        ...

    @abstractmethod
    def list_namespaces(self) -> list[dict[str, Any]]:
        """List all namespaces."""
        ...

    @abstractmethod
    def get_namespace(self, ns: str) -> dict[str, Any] | None:
        """Get namespace by ID."""
        ...

    @abstractmethod
    def delete_namespace(self, ns: str) -> bool:
        """Delete a namespace."""
        ...

    @abstractmethod
    def archive_namespace(self, ns: str, secret: str) -> bool:
        """Archive a namespace (soft delete)."""
        ...

    # --- Identity Operations ---

    @abstractmethod
    def create_identity(
        self,
        ns: str,
        display_name: str | None = None,
        metadata: dict[str, Any] | None = None,
        ns_secret: str | None = None,
    ) -> dict[str, Any]:
        """Create a new identity in a namespace.

        Args:
            ns: Namespace ID
            display_name: Human-readable name
            metadata: Additional metadata
            ns_secret: Namespace secret (required for remote, optional for local)

        Returns:
            dict with keys: id, secret, metadata
        """
        ...

    @abstractmethod
    def list_identities(
        self,
        ns: str,
        secret: str | None = None,
    ) -> list[dict[str, Any]]:
        """List identities in a namespace.

        Args:
            ns: Namespace ID
            secret: Namespace secret or inbox secret for authentication
        """
        ...

    @abstractmethod
    def get_identity(self, ns: str, identity_id: str) -> dict[str, Any] | None:
        """Get identity by ID."""
        ...

    @abstractmethod
    def delete_identity(
        self,
        ns: str,
        identity_id: str,
        ns_secret: str | None = None,
    ) -> bool:
        """Delete an identity."""
        ...

    # --- Message Operations ---

    @abstractmethod
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
            ns: Namespace ID
            from_secret: Sender's inbox secret
            to_id: Recipient identity ID
            body: Message body
            content_type: MIME type
            ttl_hours: Optional TTL for ephemeral messages

        Returns:
            dict with keys: mid, from, to, content_type, created_at
        """
        ...

    @abstractmethod
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
            ns: Namespace ID
            identity_id: Identity ID
            secret: Inbox secret
            unread_only: Only return unread messages
            after_mid: Cursor for pagination
            mark_as_read: Whether to mark messages as read
        """
        ...

    @abstractmethod
    def delete_message(
        self,
        ns: str,
        identity_id: str,
        secret: str,
        mid: str,
    ) -> bool:
        """Delete a message."""
        ...

    @abstractmethod
    def archive_message(
        self,
        ns: str,
        identity_id: str,
        secret: str,
        mid: str,
    ) -> bool:
        """Archive a message."""
        ...

    @abstractmethod
    def get_archived_messages(
        self,
        ns: str,
        identity_id: str,
        secret: str,
    ) -> list[dict[str, Any]]:
        """Get archived messages."""
        ...

    # --- Room Operations ---

    @abstractmethod
    def create_room(
        self,
        ns: str,
        creator_secret: str,
        display_name: str | None = None,
    ) -> dict[str, Any]:
        """Create a new room in a namespace.

        The creator becomes the first member automatically.

        Args:
            ns: Namespace ID
            creator_secret: Creator's inbox secret
            display_name: Optional display name for the room

        Returns:
            dict with keys: room_id, ns, display_name, created_by, created_at
        """
        ...

    @abstractmethod
    def list_rooms(
        self,
        ns: str,
        secret: str,
    ) -> list[dict[str, Any]]:
        """List rooms the caller is a member of.

        Args:
            ns: Namespace ID
            secret: Caller's inbox secret

        Returns:
            List of room dicts with membership info
        """
        ...

    @abstractmethod
    def get_room(
        self,
        ns: str,
        room_id: str,
        secret: str,
    ) -> dict[str, Any] | None:
        """Get room details. Requires membership.

        Args:
            ns: Namespace ID
            room_id: Room ID
            secret: Caller's inbox secret (must be a member)

        Returns:
            Room dict or None if not found/not a member
        """
        ...

    @abstractmethod
    def delete_room(
        self,
        ns: str,
        room_id: str,
        ns_secret: str,
    ) -> bool:
        """Delete a room. Requires namespace owner.

        Args:
            ns: Namespace ID
            room_id: Room ID
            ns_secret: Namespace secret

        Returns:
            True if deleted, False if not found
        """
        ...

    @abstractmethod
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
            ns: Namespace ID
            room_id: Room ID
            identity_id: Identity to add
            secret: Caller's inbox secret (must be a member)

        Returns:
            Member info dict
        """
        ...

    @abstractmethod
    def remove_room_member(
        self,
        ns: str,
        room_id: str,
        identity_id: str,
        secret: str,
    ) -> bool:
        """Remove a member from a room.

        Members can remove themselves or be removed by other members.

        Args:
            ns: Namespace ID
            room_id: Room ID
            identity_id: Identity to remove
            secret: Caller's inbox secret

        Returns:
            True if removed, False if not found
        """
        ...

    @abstractmethod
    def list_room_members(
        self,
        ns: str,
        room_id: str,
        secret: str,
    ) -> list[dict[str, Any]]:
        """List members of a room.

        Args:
            ns: Namespace ID
            room_id: Room ID
            secret: Caller's inbox secret (must be a member)

        Returns:
            List of member info dicts
        """
        ...

    @abstractmethod
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
            ns: Namespace ID
            room_id: Room ID
            secret: Sender's inbox secret (must be a member)
            body: Message body
            content_type: MIME type
            reference_mid: Optional message ID to reply to (thread root)

        Returns:
            Message dict
        """
        ...

    @abstractmethod
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
            ns: Namespace ID
            room_id: Room ID
            secret: Caller's inbox secret (must be a member)
            after_mid: Only get messages after this ID
            limit: Maximum messages to return
            include_replies: If False, exclude thread replies

        Returns:
            List of message dicts
        """
        ...

    @abstractmethod
    def get_thread(
        self,
        ns: str,
        room_id: str,
        secret: str,
        root_mid: str,
    ) -> dict[str, Any] | None:
        """Get a thread: root message and all replies.

        Args:
            ns: Namespace ID
            room_id: Room ID
            secret: Caller's inbox secret (must be a member)
            root_mid: Message ID of the thread root

        Returns:
            Dict with "root", "replies", "reply_count", or None if not found
        """
        ...

    @abstractmethod
    def update_room_read_cursor(
        self,
        ns: str,
        room_id: str,
        secret: str,
        last_read_mid: str,
    ) -> bool:
        """Update read cursor for the caller.

        Args:
            ns: Namespace ID
            room_id: Room ID
            secret: Caller's inbox secret (must be a member)
            last_read_mid: Message ID of last read message

        Returns:
            True if updated
        """
        ...

    @abstractmethod
    def get_room_unread_count(
        self,
        ns: str,
        room_id: str,
        secret: str,
    ) -> int:
        """Get unread message count for the caller.

        Args:
            ns: Namespace ID
            room_id: Room ID
            secret: Caller's inbox secret (must be a member)

        Returns:
            Number of unread messages
        """
        ...

    # --- Invite Methods ---

    @abstractmethod
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

        Args:
            ns: Namespace ID
            identity_id: Identity to create invite for
            identity_secret: The identity's secret (to be encrypted)
            ns_secret: Namespace secret (for authorization)
            display_name: Optional display name
            expires_at: Optional expiration (ISO 8601)

        Returns:
            dict with invite_id, invite_url, expires_at
        """
        ...

    @abstractmethod
    def claim_invite(self, invite_url: str) -> dict[str, Any]:
        """Claim an invite URL and return decrypted credentials."""
        ...

    # --- Subscription Methods ---

    def subscribe(
        self,
        ns: str,
        secret: str,
        topics: dict[str, str | None],
        timeout: int = 30,
    ) -> dict[str, Any]:
        """Subscribe to topic changes (poll mode).

        Blocks until any subscribed topic has changes or timeout.

        Args:
            ns: Namespace ID
            secret: Caller's inbox secret (for auth)
            topics: Map of topic_key -> last_seen_mid (None = never seen)
            timeout: Max seconds to wait

        Returns:
            dict with 'events' (changed topics) and 'timeout' (bool)
        """
        raise NotImplementedError("subscribe not implemented for this backend")

    def subscribe_stream(
        self,
        ns: str,
        secret: str,
        topics: dict[str, str | None],
    ):
        """Subscribe to topic changes (streaming mode).

        Returns an iterator that yields event dicts as they occur.

        Args:
            ns: Namespace ID
            secret: Caller's inbox secret (for auth)
            topics: Map of topic_key -> last_seen_mid (None = never seen)

        Yields:
            dicts with 'topic' and 'latest_mid' keys
        """
        raise NotImplementedError("subscribe_stream not implemented for this backend")

    # --- Utility Methods ---

    def verify_identity_secret(self, ns: str, identity_id: str, secret: str) -> bool:
        """Verify an identity secret is valid."""
        # Default implementation derives ID from secret
        return derive_id(secret) == identity_id

    def close(self) -> None:
        """Close any resources held by the backend."""
        pass


@dataclass
class LocalConfig:
    """Configuration stored in .deaddrop/config.yaml."""

    namespaces: dict[str, dict[str, Any]] = field(default_factory=dict)
    """Namespace registry: ns_id -> {secret, display_name, ...}"""

    @classmethod
    def load(cls, path: Path) -> "LocalConfig":
        """Load config from YAML file."""
        config_path = path / "config.yaml"
        if not config_path.exists():
            return cls()

        with open(config_path) as f:
            data = yaml.safe_load(f) or {}

        return cls(namespaces=data.get("namespaces", {}))

    def save(self, path: Path) -> None:
        """Save config to YAML file."""
        config_path = path / "config.yaml"
        data = {"namespaces": self.namespaces}

        with open(config_path, "w") as f:
            yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)


class LocalBackend(Backend):
    """Local file-system based backend using SQLite.

    Stores data in a .deaddrop directory:
    - config.yaml: Namespace registry with secrets
    - data.db: SQLite database (same schema as server)
    """

    def __init__(self, path: Path, create_if_missing: bool = False):
        """Initialize local backend.

        Args:
            path: Path to .deaddrop directory
            create_if_missing: If True, create directory if it doesn't exist
        """
        self._path = path
        self._conn: sqlite3.Connection | None = None
        self._config: LocalConfig | None = None

        if not path.exists():
            if create_if_missing:
                self._init_local()
            else:
                raise FileNotFoundError(f"Local deaddrop not found: {path}")
        else:
            self._load()

    @classmethod
    def create(
        cls,
        path: Path | None = None,
        add_to_gitignore: bool = True,
    ) -> "LocalBackend":
        """Create a new local deaddrop.

        Args:
            path: Path for .deaddrop directory. If None, uses git root or cwd.
            add_to_gitignore: Add .deaddrop/ to .gitignore if in git repo.

        Returns:
            Initialized LocalBackend instance.
        """
        if path is None:
            path = get_deaddrop_init_path()

        backend = cls(path, create_if_missing=True)

        if add_to_gitignore:
            ensure_gitignore(path)

        return backend

    def _init_local(self) -> None:
        """Initialize a new .deaddrop directory."""
        self._path.mkdir(parents=True, exist_ok=True)

        # Initialize empty config
        self._config = LocalConfig()
        self._config.save(self._path)

        # Initialize database
        db_path = self._path / "data.db"
        self._conn = db.get_connection(db_path)
        db.init_db_with_conn(self._conn)

    def _load(self) -> None:
        """Load existing .deaddrop directory."""
        self._config = LocalConfig.load(self._path)
        db_path = self._path / "data.db"
        self._conn = db.get_connection(db_path)
        db.init_db_with_conn(self._conn)

    def get_info(self) -> BackendInfo:
        return BackendInfo(backend_type="local", location=str(self._path))

    @property
    def path(self) -> Path:
        """Path to .deaddrop directory."""
        return self._path

    @property
    def config(self) -> LocalConfig:
        """Local configuration."""
        if self._config is None:
            self._config = LocalConfig.load(self._path)
        return self._config

    def _save_config(self) -> None:
        """Save config to disk."""
        if self._config:
            self._config.save(self._path)

    def close(self) -> None:
        """Close database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None

    # --- Namespace Operations ---

    def create_namespace(
        self,
        display_name: str | None = None,
        ttl_hours: int = 24,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        metadata = metadata or {}
        if display_name:
            metadata["display_name"] = display_name

        result = db.create_namespace(
            metadata=metadata,
            ttl_hours=ttl_hours,
            conn=self._conn,
        )

        # Store in local config
        ns_id = result["ns"]
        assert ns_id is not None
        self.config.namespaces[ns_id] = {
            "secret": result["secret"],
            "display_name": display_name,
            "slug": result["slug"],
        }
        self._save_config()

        return {
            "ns": result["ns"],
            "secret": result["secret"],
            "slug": result["slug"],
            "metadata": metadata,
            "ttl_hours": ttl_hours,
        }

    def list_namespaces(self) -> list[dict[str, Any]]:
        return db.list_namespaces(conn=self._conn)

    def get_namespace(self, ns: str) -> dict[str, Any] | None:
        return db.get_namespace(ns, conn=self._conn)

    def delete_namespace(self, ns: str) -> bool:
        result = db.delete_namespace(ns, conn=self._conn)
        if result and ns in self.config.namespaces:
            del self.config.namespaces[ns]
            self._save_config()
        return result

    def archive_namespace(self, ns: str, secret: str) -> bool:
        # Verify secret
        if not db.verify_namespace_secret(ns, secret, conn=self._conn):
            raise PermissionError("Invalid namespace secret")
        return db.archive_namespace(ns, conn=self._conn)

    # --- Identity Operations ---

    def create_identity(
        self,
        ns: str,
        display_name: str | None = None,
        metadata: dict[str, Any] | None = None,
        ns_secret: str | None = None,
    ) -> dict[str, Any]:
        metadata = metadata or {}
        if display_name:
            metadata["display_name"] = display_name

        result = db.create_identity(ns, metadata=metadata, conn=self._conn)
        return {
            "id": result["id"],
            "secret": result["secret"],
            "metadata": metadata,
        }

    def list_identities(
        self,
        ns: str,
        secret: str | None = None,
    ) -> list[dict[str, Any]]:
        return db.list_identities(ns, conn=self._conn)

    def get_identity(self, ns: str, identity_id: str) -> dict[str, Any] | None:
        return db.get_identity(ns, identity_id, conn=self._conn)

    def delete_identity(
        self,
        ns: str,
        identity_id: str,
        ns_secret: str | None = None,
    ) -> bool:
        return db.delete_identity(ns, identity_id, conn=self._conn)

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
        # Verify sender
        from_id = db.verify_identity_in_namespace(ns, from_secret, conn=self._conn)
        if not from_id:
            raise PermissionError("Invalid sender secret")

        return db.send_message(
            ns=ns,
            from_id=from_id,
            to_id=to_id,
            body=body,
            content_type=content_type,
            ttl_hours=ttl_hours,
            conn=self._conn,
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
        # Verify owner
        if not db.verify_identity_secret(ns, identity_id, secret, conn=self._conn):
            raise PermissionError("Invalid inbox secret")

        return db.get_messages(
            ns=ns,
            identity_id=identity_id,
            unread_only=unread_only,
            after_mid=after_mid,
            mark_as_read=mark_as_read,
            conn=self._conn,
        )

    def delete_message(
        self,
        ns: str,
        identity_id: str,
        secret: str,
        mid: str,
    ) -> bool:
        if not db.verify_identity_secret(ns, identity_id, secret, conn=self._conn):
            raise PermissionError("Invalid inbox secret")
        return db.delete_message(ns, identity_id, mid, conn=self._conn)

    def archive_message(
        self,
        ns: str,
        identity_id: str,
        secret: str,
        mid: str,
    ) -> bool:
        if not db.verify_identity_secret(ns, identity_id, secret, conn=self._conn):
            raise PermissionError("Invalid inbox secret")
        return db.archive_message(ns, identity_id, mid, conn=self._conn)

    def get_archived_messages(
        self,
        ns: str,
        identity_id: str,
        secret: str,
    ) -> list[dict[str, Any]]:
        if not db.verify_identity_secret(ns, identity_id, secret, conn=self._conn):
            raise PermissionError("Invalid inbox secret")
        return db.get_archived_messages(ns, identity_id, conn=self._conn)

    # --- Room Operations ---

    def create_room(
        self,
        ns: str,
        creator_secret: str,
        display_name: str | None = None,
    ) -> dict[str, Any]:
        # Verify creator is in namespace
        created_by = db.verify_identity_in_namespace(ns, creator_secret, conn=self._conn)
        if not created_by:
            raise PermissionError("Invalid creator secret")

        return db.create_room(ns, created_by, display_name=display_name, conn=self._conn)

    def list_rooms(
        self,
        ns: str,
        secret: str,
    ) -> list[dict[str, Any]]:
        identity_id = db.verify_identity_in_namespace(ns, secret, conn=self._conn)
        if not identity_id:
            raise PermissionError("Invalid inbox secret")

        return db.list_rooms_for_identity(ns, identity_id, conn=self._conn)

    def get_room(
        self,
        ns: str,
        room_id: str,
        secret: str,
    ) -> dict[str, Any] | None:
        identity_id = derive_id(secret)
        if not db.is_room_member(room_id, identity_id, conn=self._conn):
            raise PermissionError("Not a member of this room")

        room = db.get_room(room_id, conn=self._conn)
        if room and room.get("ns") != ns:
            return None
        return room

    def delete_room(
        self,
        ns: str,
        room_id: str,
        ns_secret: str,
    ) -> bool:
        if not db.verify_namespace_secret(ns, ns_secret, conn=self._conn):
            raise PermissionError("Invalid namespace secret")

        room = db.get_room(room_id, conn=self._conn)
        if not room or room.get("ns") != ns:
            return False

        return db.delete_room(room_id, conn=self._conn)

    def add_room_member(
        self,
        ns: str,
        room_id: str,
        identity_id: str,
        secret: str,
    ) -> dict[str, Any]:
        caller_id = derive_id(secret)
        if not db.is_room_member(room_id, caller_id, conn=self._conn):
            raise PermissionError("Not a member of this room")

        room = db.get_room(room_id, conn=self._conn)
        if not room or room.get("ns") != ns:
            raise ValueError("Room not found in this namespace")

        member = db.add_room_member(room_id, identity_id, conn=self._conn)
        # Get full member info
        member_info = db.get_room_member_info(room_id, identity_id, conn=self._conn)
        return member_info or member

    def remove_room_member(
        self,
        ns: str,
        room_id: str,
        identity_id: str,
        secret: str,
    ) -> bool:
        caller_id = derive_id(secret)

        # Can remove self or must be a member to remove others
        if caller_id != identity_id:
            if not db.is_room_member(room_id, caller_id, conn=self._conn):
                raise PermissionError("Not authorized to remove members")

        return db.remove_room_member(room_id, identity_id, conn=self._conn)

    def list_room_members(
        self,
        ns: str,
        room_id: str,
        secret: str,
    ) -> list[dict[str, Any]]:
        identity_id = derive_id(secret)
        if not db.is_room_member(room_id, identity_id, conn=self._conn):
            raise PermissionError("Not a member of this room")

        room = db.get_room(room_id, conn=self._conn)
        if not room or room.get("ns") != ns:
            raise ValueError("Room not found in this namespace")

        return db.list_room_members(room_id, conn=self._conn)

    def send_room_message(
        self,
        ns: str,
        room_id: str,
        secret: str,
        body: str,
        content_type: str = "text/plain",
        reference_mid: str | None = None,
    ) -> dict[str, Any]:
        from_id = derive_id(secret)
        if not db.is_room_member(room_id, from_id, conn=self._conn):
            raise PermissionError("Not a member of this room")

        room = db.get_room(room_id, conn=self._conn)
        if not room or room.get("ns") != ns:
            raise ValueError("Room not found in this namespace")

        return db.send_room_message(
            room_id,
            from_id,
            body,
            content_type,
            reference_mid=reference_mid,
            conn=self._conn,
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
        identity_id = derive_id(secret)
        if not db.is_room_member(room_id, identity_id, conn=self._conn):
            raise PermissionError("Not a member of this room")

        room = db.get_room(room_id, conn=self._conn)
        if not room or room.get("ns") != ns:
            raise ValueError("Room not found in this namespace")

        include_thread_meta = not include_replies
        return db.get_room_messages(
            room_id,
            after_mid=after_mid,
            limit=limit,
            include_replies=include_replies,
            include_thread_meta=include_thread_meta,
            conn=self._conn,
        )

    def get_thread(
        self,
        ns: str,
        room_id: str,
        secret: str,
        root_mid: str,
    ) -> dict[str, Any] | None:
        identity_id = derive_id(secret)
        if not db.is_room_member(room_id, identity_id, conn=self._conn):
            raise PermissionError("Not a member of this room")

        room = db.get_room(room_id, conn=self._conn)
        if not room or room.get("ns") != ns:
            raise ValueError("Room not found in this namespace")

        return db.get_thread(room_id, root_mid, conn=self._conn)

    def update_room_read_cursor(
        self,
        ns: str,
        room_id: str,
        secret: str,
        last_read_mid: str,
    ) -> bool:
        identity_id = derive_id(secret)
        if not db.is_room_member(room_id, identity_id, conn=self._conn):
            raise PermissionError("Not a member of this room")

        return db.update_room_read_cursor(room_id, identity_id, last_read_mid, conn=self._conn)

    def get_room_unread_count(
        self,
        ns: str,
        room_id: str,
        secret: str,
    ) -> int:
        identity_id = derive_id(secret)
        if not db.is_room_member(room_id, identity_id, conn=self._conn):
            raise PermissionError("Not a member of this room")

        return db.get_room_unread_count(room_id, identity_id, conn=self._conn)

    # --- Local-specific Methods ---

    def get_namespace_secret(self, ns: str) -> str | None:
        """Get namespace secret from local config."""
        ns_config = self.config.namespaces.get(ns)
        return ns_config["secret"] if ns_config else None

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
        """Create an invite for an identity (local backend).

        Creates an invite URL using the local:// scheme that encodes
        the database path and invite ID with the encryption key in the fragment.

        URL format: local://{db_path}/join/{invite_id}#{key_base64}
        """
        from .crypto import create_invite_secrets

        # Verify namespace access
        if not db.verify_namespace_secret(ns, ns_secret, conn=self._conn):
            raise PermissionError("Invalid namespace secret")

        # Generate invite secrets (encrypts the identity secret)
        invite_secrets = create_invite_secrets(identity_secret)

        # Store invite in database
        result = db.create_invite(
            invite_id=invite_secrets.invite_id,
            ns=ns,
            identity_id=identity_id,
            encrypted_secret=invite_secrets.encrypted_secret_hex,
            display_name=display_name,
            created_by=identity_id,  # Creator is the identity being shared
            expires_at=expires_at,
            conn=self._conn,
        )

        # Build the invite URL with local:// scheme
        # Use the database path so claim_invite knows where to look
        db_path = str(self._path)
        invite_url = (
            f"local://{db_path}/join/{invite_secrets.invite_id}#{invite_secrets.key_base64}"
        )

        return {
            "invite_id": invite_secrets.invite_id,
            "invite_url": invite_url,
            "expires_at": result.get("expires_at"),
        }

    def claim_invite(self, invite_url: str) -> dict[str, Any]:
        """Claim an invite URL (local backend).

        Parses a local:// invite URL and returns decrypted credentials.

        URL format: local://{db_path}/join/{invite_id}#{key_base64}
        """
        import re
        from urllib.parse import urlparse
        from .crypto import decrypt_invite_secret

        # Parse the invite URL
        parsed = urlparse(invite_url)

        if parsed.scheme != "local":
            raise ValueError(f"Invalid invite URL scheme: {parsed.scheme} (expected 'local')")

        fragment = parsed.fragment  # The encryption key
        path = parsed.path

        # Extract invite_id from path
        match = re.search(r"/join/([a-f0-9]+)$", path)
        if not match:
            raise ValueError(f"Invalid invite URL format: {invite_url}")

        invite_id = match.group(1)

        # Claim from database
        result = db.claim_invite(
            invite_id=invite_id,
            claimed_by="local_claim",
            conn=self._conn,
        )

        if not result:
            raise ValueError(f"Invite not found or already claimed: {invite_id}")

        # Decrypt the secret using the key from the URL fragment
        encrypted_secret = result["encrypted_secret"]
        identity_secret = decrypt_invite_secret(encrypted_secret, fragment, invite_id)

        return {
            "ns": result["ns"],
            "identity_id": result["identity_id"],
            "secret": identity_secret,
            "display_name": result.get("display_name"),
        }

    def subscribe(
        self,
        ns: str,
        secret: str,
        topics: dict[str, str | None],
        timeout: int = 30,
    ) -> dict[str, Any]:
        """Subscribe to topic changes using the in-memory event bus.

        For local backends, we use the event bus directly since
        publish events from send_message/send_room_message go through
        the same process.
        """
        import asyncio

        from .events import get_event_bus

        # Validate identity
        identity_id = db.verify_identity_in_namespace(ns, secret, conn=self._conn)
        if not identity_id:
            raise ValueError("Invalid inbox secret or not in namespace")

        # Validate topics
        for topic_key in topics:
            if ":" not in topic_key:
                raise ValueError(f"Invalid topic format: {topic_key}")
            topic_type, topic_id = topic_key.split(":", 1)
            if topic_type == "inbox" and topic_id != identity_id:
                raise ValueError("Cannot subscribe to another identity's inbox")
            elif topic_type == "room":
                if not db.is_room_member(topic_id, identity_id, conn=self._conn):
                    raise ValueError(f"Not a member of room: {topic_id}")

        event_bus = get_event_bus()
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            changes = loop.run_until_complete(event_bus.subscribe(ns, topics, timeout=timeout))
            loop.close()
        else:
            changes = loop.run_until_complete(event_bus.subscribe(ns, topics, timeout=timeout))

        return {"events": changes, "timeout": len(changes) == 0}

    def subscribe_stream(
        self,
        ns: str,
        secret: str,
        topics: dict[str, str | None],
    ):
        """Subscribe to topic changes using in-memory event bus (streaming)."""
        import asyncio

        from .events import get_event_bus

        # Validate identity
        identity_id = db.verify_identity_in_namespace(ns, secret, conn=self._conn)
        if not identity_id:
            raise ValueError("Invalid inbox secret or not in namespace")

        event_bus = get_event_bus()

        # Use a synchronous wrapper around the async stream
        loop = asyncio.new_event_loop()
        try:
            stream = event_bus.stream(ns, topics)
            while True:
                event = loop.run_until_complete(stream.__anext__())
                yield event
        except StopAsyncIteration:
            pass
        finally:
            loop.close()


class RemoteBackend(Backend):
    """Remote HTTP API backend.

    Connects to a deaddrop server via HTTP API.
    """

    def __init__(
        self,
        url: str,
        bearer_token: str | None = None,
    ):
        """Initialize remote backend.

        Args:
            url: Base URL of the deaddrop server
            bearer_token: Bearer token for admin operations
        """
        import httpx

        self._url = url.rstrip("/")
        self._bearer_token = bearer_token
        self._client = httpx.Client(timeout=30.0)

    def get_info(self) -> BackendInfo:
        return BackendInfo(backend_type="remote", location=self._url)

    def close(self) -> None:
        """Close HTTP client."""
        self._client.close()

    def _request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> Any:
        """Make an HTTP request."""
        url = f"{self._url}{path}"
        request_headers = headers or {}

        response = self._client.request(
            method,
            url,
            json=json,
            headers=request_headers,
            timeout=timeout,
        )

        if response.status_code >= 400:
            raise RuntimeError(f"API error {response.status_code}: {response.text}")

        if response.status_code == 204 or not response.content:
            return None

        return response.json()

    def _admin_headers(self) -> dict[str, str]:
        """Get headers for admin operations.

        Returns empty dict if no bearer token (for no-auth servers).
        """
        if not self._bearer_token:
            return {}
        return {"Authorization": f"Bearer {self._bearer_token}"}

    def _ns_headers(self, ns_secret: str) -> dict[str, str]:
        """Get headers for namespace owner operations."""
        return {"X-Namespace-Secret": ns_secret}

    def _inbox_headers(self, inbox_secret: str) -> dict[str, str]:
        """Get headers for mailbox owner operations."""
        return {"X-Inbox-Secret": inbox_secret}

    # --- Namespace Operations ---

    def create_namespace(
        self,
        display_name: str | None = None,
        ttl_hours: int = 24,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        metadata = metadata or {}
        if display_name:
            metadata["display_name"] = display_name

        result = self._request(
            "POST",
            "/admin/namespaces",
            json={"metadata": metadata, "ttl_hours": ttl_hours},
            headers=self._admin_headers(),
        )
        return result

    def list_namespaces(self) -> list[dict[str, Any]]:
        return self._request(
            "GET",
            "/admin/namespaces",
            headers=self._admin_headers(),
        )

    def get_namespace(self, ns: str) -> dict[str, Any] | None:
        try:
            return self._request(
                "GET",
                f"/admin/namespaces/{ns}",
                headers=self._admin_headers(),
            )
        except RuntimeError as e:
            if "404" in str(e):
                return None
            raise

    def delete_namespace(self, ns: str) -> bool:
        try:
            self._request(
                "DELETE",
                f"/admin/namespaces/{ns}",
                headers=self._admin_headers(),
            )
            return True
        except RuntimeError:
            return False

    def archive_namespace(self, ns: str, secret: str) -> bool:
        try:
            self._request(
                "POST",
                f"/{ns}/archive",
                headers=self._ns_headers(secret),
            )
            return True
        except RuntimeError:
            return False

    # --- Identity Operations ---

    def create_identity(
        self,
        ns: str,
        display_name: str | None = None,
        metadata: dict[str, Any] | None = None,
        ns_secret: str | None = None,
    ) -> dict[str, Any]:
        if not ns_secret:
            raise PermissionError("Namespace secret required to create identity")

        metadata = metadata or {}
        if display_name:
            metadata["display_name"] = display_name

        result = self._request(
            "POST",
            f"/{ns}/identities",
            json={"metadata": metadata} if metadata else None,
            headers=self._ns_headers(ns_secret),
        )
        return result

    def list_identities(
        self,
        ns: str,
        secret: str | None = None,
    ) -> list[dict[str, Any]]:
        if not secret:
            raise PermissionError("Secret required to list identities")

        # Try as namespace secret first, fall back to inbox secret
        headers = {"X-Namespace-Secret": secret}
        try:
            return self._request("GET", f"/{ns}/identities", headers=headers)
        except RuntimeError:
            headers = {"X-Inbox-Secret": secret}
            return self._request("GET", f"/{ns}/identities", headers=headers)

    def get_identity(self, ns: str, identity_id: str) -> dict[str, Any] | None:
        # This requires auth - for now return None
        # In practice, users would use list_identities
        return None

    def delete_identity(
        self,
        ns: str,
        identity_id: str,
        ns_secret: str | None = None,
    ) -> bool:
        if not ns_secret:
            raise PermissionError("Namespace secret required to delete identity")

        try:
            self._request(
                "DELETE",
                f"/{ns}/identities/{identity_id}",
                headers=self._ns_headers(ns_secret),
            )
            return True
        except RuntimeError:
            return False

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
        json_data: dict[str, Any] = {
            "to": to_id,
            "body": body,
            "content_type": content_type,
        }
        if ttl_hours is not None:
            json_data["ttl_hours"] = ttl_hours

        result = self._request(
            "POST",
            f"/{ns}/send",
            json=json_data,
            headers=self._inbox_headers(from_secret),
        )
        return result

    def get_inbox(
        self,
        ns: str,
        identity_id: str,
        secret: str,
        unread_only: bool = False,
        after_mid: str | None = None,
        mark_as_read: bool = True,
    ) -> list[dict[str, Any]]:
        params = []
        if unread_only:
            params.append("unread=true")
        if after_mid:
            params.append(f"after={after_mid}")

        path = f"/{ns}/inbox/{identity_id}"
        if params:
            path += "?" + "&".join(params)

        result = self._request(
            "GET",
            path,
            headers=self._inbox_headers(secret),
        )
        return result.get("messages", [])

    def delete_message(
        self,
        ns: str,
        identity_id: str,
        secret: str,
        mid: str,
    ) -> bool:
        try:
            self._request(
                "DELETE",
                f"/{ns}/inbox/{identity_id}/{mid}",
                headers=self._inbox_headers(secret),
            )
            return True
        except RuntimeError:
            return False

    def archive_message(
        self,
        ns: str,
        identity_id: str,
        secret: str,
        mid: str,
    ) -> bool:
        try:
            self._request(
                "POST",
                f"/{ns}/inbox/{identity_id}/{mid}/archive",
                headers=self._inbox_headers(secret),
            )
            return True
        except RuntimeError:
            return False

    def get_archived_messages(
        self,
        ns: str,
        identity_id: str,
        secret: str,
    ) -> list[dict[str, Any]]:
        result = self._request(
            "GET",
            f"/{ns}/inbox/{identity_id}/archived",
            headers=self._inbox_headers(secret),
        )
        return result.get("messages", [])

    # --- Room Operations ---

    def create_room(
        self,
        ns: str,
        creator_secret: str,
        display_name: str | None = None,
    ) -> dict[str, Any]:
        json_data: dict[str, Any] = {}
        if display_name:
            json_data["display_name"] = display_name

        return self._request(
            "POST",
            f"/{ns}/rooms",
            json=json_data if json_data else None,
            headers=self._inbox_headers(creator_secret),
        )

    def list_rooms(
        self,
        ns: str,
        secret: str,
    ) -> list[dict[str, Any]]:
        return self._request(
            "GET",
            f"/{ns}/rooms",
            headers=self._inbox_headers(secret),
        )

    def get_room(
        self,
        ns: str,
        room_id: str,
        secret: str,
    ) -> dict[str, Any] | None:
        try:
            return self._request(
                "GET",
                f"/{ns}/rooms/{room_id}",
                headers=self._inbox_headers(secret),
            )
        except RuntimeError as e:
            if "404" in str(e) or "403" in str(e):
                return None
            raise

    def delete_room(
        self,
        ns: str,
        room_id: str,
        ns_secret: str,
    ) -> bool:
        try:
            self._request(
                "DELETE",
                f"/{ns}/rooms/{room_id}",
                headers=self._ns_headers(ns_secret),
            )
            return True
        except RuntimeError:
            return False

    def add_room_member(
        self,
        ns: str,
        room_id: str,
        identity_id: str,
        secret: str,
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/{ns}/rooms/{room_id}/members",
            json={"identity_id": identity_id},
            headers=self._inbox_headers(secret),
        )

    def remove_room_member(
        self,
        ns: str,
        room_id: str,
        identity_id: str,
        secret: str,
    ) -> bool:
        try:
            self._request(
                "DELETE",
                f"/{ns}/rooms/{room_id}/members/{identity_id}",
                headers=self._inbox_headers(secret),
            )
            return True
        except RuntimeError:
            return False

    def list_room_members(
        self,
        ns: str,
        room_id: str,
        secret: str,
    ) -> list[dict[str, Any]]:
        return self._request(
            "GET",
            f"/{ns}/rooms/{room_id}/members",
            headers=self._inbox_headers(secret),
        )

    def send_room_message(
        self,
        ns: str,
        room_id: str,
        secret: str,
        body: str,
        content_type: str = "text/plain",
        reference_mid: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"body": body, "content_type": content_type}
        if reference_mid is not None:
            payload["reference_mid"] = reference_mid
        return self._request(
            "POST",
            f"/{ns}/rooms/{room_id}/messages",
            json=payload,
            headers=self._inbox_headers(secret),
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
        params = []
        if after_mid:
            params.append(f"after={after_mid}")
        if limit != 100:
            params.append(f"limit={limit}")
        if not include_replies:
            params.append("include_replies=false")

        path = f"/{ns}/rooms/{room_id}/messages"
        if params:
            path += "?" + "&".join(params)

        result = self._request(
            "GET",
            path,
            headers=self._inbox_headers(secret),
        )
        return result.get("messages", [])

    def get_thread(
        self,
        ns: str,
        room_id: str,
        secret: str,
        root_mid: str,
    ) -> dict[str, Any] | None:
        try:
            return self._request(
                "GET",
                f"/{ns}/rooms/{room_id}/threads/{root_mid}",
                headers=self._inbox_headers(secret),
            )
        except Exception:
            return None

    def update_room_read_cursor(
        self,
        ns: str,
        room_id: str,
        secret: str,
        last_read_mid: str,
    ) -> bool:
        try:
            self._request(
                "POST",
                f"/{ns}/rooms/{room_id}/read",
                json={"last_read_mid": last_read_mid},
                headers=self._inbox_headers(secret),
            )
            return True
        except RuntimeError:
            return False

    def get_room_unread_count(
        self,
        ns: str,
        room_id: str,
        secret: str,
    ) -> int:
        result = self._request(
            "GET",
            f"/{ns}/rooms/{room_id}/unread",
            headers=self._inbox_headers(secret),
        )
        return result.get("unread_count", 0)

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
        """Create an invite for an identity."""
        from .crypto import create_invite_secrets

        # Generate invite secrets (encrypts the identity secret)
        invite_secrets = create_invite_secrets(identity_secret)

        # Send to server
        result = self._request(
            "POST",
            f"/{ns}/invites",
            json={
                "identity_id": identity_id,
                "invite_id": invite_secrets.invite_id,
                "encrypted_secret": invite_secrets.encrypted_secret_hex,
                "display_name": display_name,
                "expires_at": expires_at,
            },
            headers=self._ns_headers(ns_secret),
        )

        # Build the invite URL with the encryption key in the fragment
        invite_url = f"{self._url}/join/{invite_secrets.invite_id}#{invite_secrets.key_base64}"

        return {
            "invite_id": invite_secrets.invite_id,
            "invite_url": invite_url,
            "expires_at": result.get("expires_at"),
        }

    def claim_invite(self, invite_url: str) -> dict[str, Any]:
        """Claim an invite URL and return decrypted credentials."""
        import re
        from urllib.parse import urlparse
        from .crypto import decrypt_invite_secret

        # Parse the invite URL: https://server/join/{invite_id}#{key}
        parsed = urlparse(invite_url)
        fragment = parsed.fragment  # The encryption key
        path = parsed.path

        # Extract invite_id from path
        match = re.match(r"/join/([a-f0-9]+)", path)
        if not match:
            raise ValueError(f"Invalid invite URL format: {invite_url}")

        invite_id = match.group(1)

        # Claim from server
        result = self._request("POST", f"/api/invites/{invite_id}/claim")

        # Decrypt the secret using the key from the URL fragment
        encrypted_secret = result["encrypted_secret"]
        identity_secret = decrypt_invite_secret(encrypted_secret, fragment, invite_id)

        return {
            "ns": result["ns"],
            "identity_id": result["identity_id"],
            "secret": identity_secret,
            "display_name": result.get("identity_display_name"),
        }

    def subscribe(
        self,
        ns: str,
        secret: str,
        topics: dict[str, str | None],
        timeout: int = 30,
    ) -> dict[str, Any]:
        """Subscribe to topic changes via the HTTP API (poll mode)."""
        response = self._client.post(
            f"{self._url}/{ns}/subscribe",
            headers={"X-Inbox-Secret": secret},
            json={"topics": topics, "mode": "poll", "timeout": timeout},
            timeout=max(30.0, timeout + 5),
        )

        if response.status_code != 200:
            error = response.json().get("detail", response.text)
            raise ValueError(f"Subscribe failed: {error}")

        return response.json()

    def subscribe_stream(
        self,
        ns: str,
        secret: str,
        topics: dict[str, str | None],
    ):
        """Subscribe to topic changes via SSE stream.

        Yields event dicts with 'topic' and 'latest_mid' keys.
        """
        import json

        with self._client.stream(
            "POST",
            f"{self._url}/{ns}/subscribe",
            headers={"X-Inbox-Secret": secret},
            json={"topics": topics, "mode": "stream"},
            timeout=None,  # SSE streams are long-lived
        ) as response:
            if response.status_code != 200:
                raise ValueError(f"Subscribe stream failed: {response.status_code}")

            buffer = ""
            for chunk in response.iter_text():
                buffer += chunk
                # Parse SSE events from buffer
                while "\n\n" in buffer:
                    block, buffer = buffer.split("\n\n", 1)
                    if not block.strip():
                        continue

                    event_type = "message"
                    event_data = ""
                    for line in block.split("\n"):
                        if line.startswith("event: "):
                            event_type = line[7:].strip()
                        elif line.startswith("data: "):
                            event_data = line[6:]

                    if event_type == "change" and event_data:
                        try:
                            yield json.loads(event_data)
                        except json.JSONDecodeError:
                            pass


class InMemoryBackend(LocalBackend):
    """In-memory backend for testing.

    Uses SQLite's :memory: database. All data is lost when the backend
    is closed or garbage collected.
    """

    def __init__(self):
        """Initialize in-memory backend."""
        self._path = Path(":memory:")
        self._config = LocalConfig()
        self._conn = db.get_connection(":memory:")
        db.init_db_with_conn(self._conn)

    def get_info(self) -> BackendInfo:
        return BackendInfo(backend_type="in_memory", location=":memory:")

    def _save_config(self) -> None:
        """No-op for in-memory backend."""
        pass

    @classmethod
    def create(
        cls,
        path: Path | None = None,
        add_to_gitignore: bool = True,
    ) -> "InMemoryBackend":
        """Create an in-memory backend (path and add_to_gitignore are ignored)."""
        return cls()
