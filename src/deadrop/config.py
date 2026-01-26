"""Configuration management for deadrop CLI.

Manages configuration files in ~/.config/deadrop/:
- config.yaml: Global config (URL, bearer token, sources)
- namespaces/{ns_hash}.yaml: Per-namespace config with mailbox credentials

Multi-source support:
- Sources define remote servers and local .deaddrop paths
- Each source has a name, type (remote/local), and connection info
- Commands accept --source to specify which source to use
"""

import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

import yaml


def get_config_dir() -> Path:
    """Get the configuration directory path."""
    config_home = os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))
    return Path(config_home) / "deadrop"


def get_global_config_path() -> Path:
    """Get the global config file path."""
    return get_config_dir() / "config.yaml"


def get_namespaces_dir() -> Path:
    """Get the namespaces directory path."""
    return get_config_dir() / "namespaces"


def ensure_config_dir() -> Path:
    """Ensure config directory exists and return its path."""
    config_dir = get_config_dir()
    config_dir.mkdir(parents=True, exist_ok=True)
    get_namespaces_dir().mkdir(parents=True, exist_ok=True)
    return config_dir


DEFAULT_SERVER_URL = "https://deaddrop.dokku.heare.io"


@dataclass
class Source:
    """A deaddrop source (remote server or local directory)."""

    name: str
    type: Literal["remote", "local"]
    url: str | None = None  # For remote sources
    path: str | None = None  # For local sources
    bearer_token: str | None = None  # For remote sources

    def to_dict(self) -> dict:
        """Convert to dictionary for YAML serialization."""
        data: dict[str, Any] = {
            "name": self.name,
            "type": self.type,
        }
        if self.type == "remote":
            data["url"] = self.url
            if self.bearer_token:
                data["bearer_token"] = self.bearer_token
        else:
            data["path"] = self.path
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "Source":
        """Create from dictionary."""
        return cls(
            name=data["name"],
            type=data["type"],
            url=data.get("url"),
            path=data.get("path"),
            bearer_token=data.get("bearer_token"),
        )

    def get_client(self):
        """Get a Deaddrop client for this source."""
        from .client import Deaddrop

        if self.type == "remote":
            assert self.url is not None
            return Deaddrop.remote(url=self.url, bearer_token=self.bearer_token)
        else:
            return Deaddrop.local(path=self.path)


@dataclass
class GlobalConfig:
    """Global CLI configuration."""

    url: str = DEFAULT_SERVER_URL
    bearer_token: str | None = None
    sources: list[Source] = field(default_factory=list)
    default_source: str | None = None

    def save(self) -> None:
        """Save config to file."""
        ensure_config_dir()
        path = get_global_config_path()

        data: dict[str, Any] = {"url": self.url}
        if self.bearer_token:
            data["bearer_token"] = self.bearer_token

        if self.sources:
            data["sources"] = [s.to_dict() for s in self.sources]
        if self.default_source:
            data["default_source"] = self.default_source

        with open(path, "w") as f:
            yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)

    @classmethod
    def load(cls) -> "GlobalConfig":
        """Load config from file, or return defaults."""
        path = get_global_config_path()

        if not path.exists():
            return cls()

        with open(path) as f:
            data = yaml.safe_load(f) or {}

        sources = []
        for s_data in data.get("sources", []):
            sources.append(Source.from_dict(s_data))

        return cls(
            url=data.get("url", DEFAULT_SERVER_URL),
            bearer_token=data.get("bearer_token"),
            sources=sources,
            default_source=data.get("default_source"),
        )

    @classmethod
    def exists(cls) -> bool:
        """Check if config file exists."""
        return get_global_config_path().exists()

    def get_source(self, name: str) -> Source | None:
        """Get a source by name."""
        for source in self.sources:
            if source.name == name:
                return source
        return None

    def add_source(self, source: Source) -> None:
        """Add a source, replacing if name exists."""
        self.sources = [s for s in self.sources if s.name != source.name]
        self.sources.append(source)

    def remove_source(self, name: str) -> bool:
        """Remove a source by name. Returns True if found."""
        original_len = len(self.sources)
        self.sources = [s for s in self.sources if s.name != name]
        if self.default_source == name:
            self.default_source = None
        return len(self.sources) < original_len

    def get_default_source(self) -> Source | None:
        """Get the default source, if set and exists."""
        if not self.default_source:
            return None
        return self.get_source(self.default_source)


@dataclass
class MailboxConfig:
    """Configuration for a single mailbox."""

    id: str
    secret: str
    display_name: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str | None = None

    def to_dict(self) -> dict:
        """Convert to dictionary for YAML serialization."""
        data = {
            "secret": self.secret,
        }
        if self.display_name:
            data["display_name"] = self.display_name
        if self.metadata:
            data["metadata"] = self.metadata
        if self.created_at:
            data["created_at"] = self.created_at
        return data

    @classmethod
    def from_dict(cls, id: str, data: dict) -> "MailboxConfig":
        """Create from dictionary."""
        return cls(
            id=id,
            secret=data["secret"],
            display_name=data.get("display_name"),
            metadata=data.get("metadata", {}),
            created_at=data.get("created_at"),
        )


@dataclass
class NamespaceConfig:
    """Configuration for a namespace with its mailboxes."""

    ns: str
    secret: str
    display_name: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str | None = None
    mailboxes: dict[str, MailboxConfig] = field(default_factory=dict)

    def get_path(self) -> Path:
        """Get the config file path for this namespace."""
        return get_namespaces_dir() / f"{self.ns}.yaml"

    def save(self) -> None:
        """Save namespace config to file."""
        ensure_config_dir()
        path = self.get_path()

        data = {
            "ns": self.ns,
            "secret": self.secret,
        }
        if self.display_name:
            data["display_name"] = self.display_name
        if self.metadata:
            data["metadata"] = self.metadata
        if self.created_at:
            data["created_at"] = self.created_at

        if self.mailboxes:
            data["mailboxes"] = {id: mb.to_dict() for id, mb in self.mailboxes.items()}

        with open(path, "w") as f:
            yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)

    @classmethod
    def load(cls, ns: str) -> "NamespaceConfig | None":
        """Load namespace config from file."""
        path = get_namespaces_dir() / f"{ns}.yaml"

        if not path.exists():
            return None

        with open(path) as f:
            data = yaml.safe_load(f) or {}

        mailboxes = {}
        for id, mb_data in data.get("mailboxes", {}).items():
            mailboxes[id] = MailboxConfig.from_dict(id, mb_data)

        return cls(
            ns=data["ns"],
            secret=data["secret"],
            display_name=data.get("display_name"),
            metadata=data.get("metadata", {}),
            created_at=data.get("created_at"),
            mailboxes=mailboxes,
        )

    @classmethod
    def list_all(cls) -> list[str]:
        """List all namespace IDs with config files."""
        ns_dir = get_namespaces_dir()
        if not ns_dir.exists():
            return []

        return [p.stem for p in ns_dir.glob("*.yaml")]

    def add_mailbox(
        self,
        id: str,
        secret: str,
        display_name: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> MailboxConfig:
        """Add a mailbox to this namespace."""
        mailbox = MailboxConfig(
            id=id,
            secret=secret,
            display_name=display_name,
            metadata=metadata or {},
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self.mailboxes[id] = mailbox
        return mailbox

    def remove_mailbox(self, id: str) -> bool:
        """Remove a mailbox from this namespace."""
        if id in self.mailboxes:
            del self.mailboxes[id]
            return True
        return False

    def delete(self) -> bool:
        """Delete the namespace config file."""
        path = self.get_path()
        if path.exists():
            path.unlink()
            return True
        return False


def init_wizard() -> GlobalConfig:
    """Interactive wizard for initial configuration."""
    print("Welcome to deadrop!")
    print("Let's set up your configuration.\n")

    # URL
    url = input(f"Deadrop server URL [{DEFAULT_SERVER_URL}]: ").strip()
    if not url:
        url = DEFAULT_SERVER_URL

    # Bearer token
    print("\nFor admin operations (creating namespaces), you need a bearer token.")
    print("This is typically from a heare-auth service.")
    print("Leave blank if using --no-auth mode for development.\n")

    bearer_token = input("Bearer token (optional): ").strip()
    if not bearer_token:
        bearer_token = None

    config = GlobalConfig(url=url, bearer_token=bearer_token)
    config.save()

    print(f"\nConfiguration saved to {get_global_config_path()}")
    return config
