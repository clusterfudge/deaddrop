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
        wait: int = 0,
    ) -> list[dict[str, Any]]:
        """Get messages for an identity.

        Args:
            ns: Namespace ID
            identity_id: Identity ID
            secret: Inbox secret
            unread_only: Only return unread messages
            after_mid: Cursor for pagination
            mark_as_read: Whether to mark messages as read
            wait: Long-poll timeout in seconds (0-60). If no messages,
                  wait up to this many seconds for new messages.
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
    ) -> dict[str, Any]:
        """Send a message to a room.

        Args:
            ns: Namespace ID
            room_id: Room ID
            secret: Sender's inbox secret (must be a member)
            body: Message body
            content_type: MIME type

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
        wait: int = 0,
    ) -> list[dict[str, Any]]:
        """Get messages from a room.

        Args:
            ns: Namespace ID
            room_id: Room ID
            secret: Caller's inbox secret (must be a member)
            after_mid: Only get messages after this ID
            limit: Maximum messages to return
            wait: Long-poll timeout in seconds

        Returns:
            List of message dicts
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
        wait: int = 0,
    ) -> list[dict[str, Any]]:
        import time

        # Verify owner
        if not db.verify_identity_secret(ns, identity_id, secret, conn=self._conn):
            raise PermissionError("Invalid inbox secret")

        # Long-polling: wait for messages if none exist and wait > 0
        if wait > 0:
            poll_interval = 0.5  # Check every 500ms
            elapsed = 0.0
            max_wait = min(wait, 60)  # Cap at 60 seconds

            while elapsed < max_wait:
                if db.has_new_messages(
                    ns, identity_id, after_mid=after_mid, unread_only=unread_only, conn=self._conn
                ):
                    break
                time.sleep(poll_interval)
                elapsed += poll_interval

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
    ) -> dict[str, Any]:
        from_id = derive_id(secret)
        if not db.is_room_member(room_id, from_id, conn=self._conn):
            raise PermissionError("Not a member of this room")

        room = db.get_room(room_id, conn=self._conn)
        if not room or room.get("ns") != ns:
            raise ValueError("Room not found in this namespace")

        return db.send_room_message(room_id, from_id, body, content_type, conn=self._conn)

    def get_room_messages(
        self,
        ns: str,
        room_id: str,
        secret: str,
        after_mid: str | None = None,
        limit: int = 100,
        wait: int = 0,
    ) -> list[dict[str, Any]]:
        import time

        identity_id = derive_id(secret)
        if not db.is_room_member(room_id, identity_id, conn=self._conn):
            raise PermissionError("Not a member of this room")

        room = db.get_room(room_id, conn=self._conn)
        if not room or room.get("ns") != ns:
            raise ValueError("Room not found in this namespace")

        # Long-polling
        if wait > 0:
            poll_interval = 0.5
            elapsed = 0.0
            max_wait = min(wait, 60)

            while elapsed < max_wait:
                if db.has_new_room_messages(room_id, after_mid=after_mid, conn=self._conn):
                    break
                time.sleep(poll_interval)
                elapsed += poll_interval

        return db.get_room_messages(room_id, after_mid=after_mid, limit=limit, conn=self._conn)

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
        wait: int = 0,
    ) -> list[dict[str, Any]]:
        params = []
        if unread_only:
            params.append("unread=true")
        if after_mid:
            params.append(f"after={after_mid}")
        if wait > 0:
            params.append(f"wait={min(wait, 60)}")

        path = f"/{ns}/inbox/{identity_id}"
        if params:
            path += "?" + "&".join(params)

        # For long-polling, we need a longer timeout
        timeout = max(30.0, wait + 5) if wait > 0 else 30.0

        result = self._request(
            "GET",
            path,
            headers=self._inbox_headers(secret),
            timeout=timeout,
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
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/{ns}/rooms/{room_id}/messages",
            json={"body": body, "content_type": content_type},
            headers=self._inbox_headers(secret),
        )

    def get_room_messages(
        self,
        ns: str,
        room_id: str,
        secret: str,
        after_mid: str | None = None,
        limit: int = 100,
        wait: int = 0,
    ) -> list[dict[str, Any]]:
        params = []
        if after_mid:
            params.append(f"after={after_mid}")
        if limit != 100:
            params.append(f"limit={limit}")
        if wait > 0:
            params.append(f"wait={min(wait, 60)}")

        path = f"/{ns}/rooms/{room_id}/messages"
        if params:
            path += "?" + "&".join(params)

        timeout = max(30.0, wait + 5) if wait > 0 else 30.0

        result = self._request(
            "GET",
            path,
            headers=self._inbox_headers(secret),
            timeout=timeout,
        )
        return result.get("messages", [])

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
