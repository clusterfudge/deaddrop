"""Tests for deadrop configuration management."""

import tempfile
from pathlib import Path

import pytest

from deadrop.config import (
    GlobalConfig,
    MailboxConfig,
    NamespaceConfig,
    Source,
)


@pytest.fixture
def temp_config_dir(monkeypatch):
    """Use a temporary directory for config."""
    with tempfile.TemporaryDirectory() as tmpdir:
        monkeypatch.setenv("XDG_CONFIG_HOME", tmpdir)
        yield Path(tmpdir) / "deadrop"


class TestGlobalConfig:
    def test_default_values(self, temp_config_dir):
        config = GlobalConfig()
        assert config.url == "https://deaddrop.dokku.heare.io"
        assert config.bearer_token is None

    def test_save_and_load(self, temp_config_dir):
        config = GlobalConfig(
            url="https://deadrop.example.com",
            bearer_token="secret-token-123",
        )
        config.save()

        loaded = GlobalConfig.load()
        assert loaded.url == "https://deadrop.example.com"
        assert loaded.bearer_token == "secret-token-123"

    def test_load_returns_defaults_when_no_file(self, temp_config_dir):
        config = GlobalConfig.load()
        assert config.url == "https://deaddrop.dokku.heare.io"
        assert config.bearer_token is None

    def test_exists(self, temp_config_dir):
        assert GlobalConfig.exists() is False

        config = GlobalConfig()
        config.save()

        assert GlobalConfig.exists() is True


class TestNamespaceConfig:
    def test_save_and_load(self, temp_config_dir):
        ns_config = NamespaceConfig(
            ns="abc123",
            secret="secret-ns-key",
            display_name="Test Namespace",
            metadata={"env": "test"},
        )
        ns_config.save()

        loaded = NamespaceConfig.load("abc123")
        assert loaded is not None
        assert loaded.ns == "abc123"
        assert loaded.secret == "secret-ns-key"
        assert loaded.display_name == "Test Namespace"
        assert loaded.metadata == {"env": "test"}

    def test_load_returns_none_when_not_found(self, temp_config_dir):
        assert NamespaceConfig.load("nonexistent") is None

    def test_list_all(self, temp_config_dir):
        # Create a few namespaces
        NamespaceConfig(ns="ns1", secret="s1").save()
        NamespaceConfig(ns="ns2", secret="s2").save()
        NamespaceConfig(ns="ns3", secret="s3").save()

        namespaces = NamespaceConfig.list_all()
        assert set(namespaces) == {"ns1", "ns2", "ns3"}

    def test_add_mailbox(self, temp_config_dir):
        ns_config = NamespaceConfig(ns="abc123", secret="ns-secret")

        mb = ns_config.add_mailbox(
            id="mb1",
            secret="mb-secret",
            display_name="Mailbox 1",
            metadata={"role": "worker"},
        )

        assert mb.id == "mb1"
        assert mb.secret == "mb-secret"
        assert mb.display_name == "Mailbox 1"
        assert "mb1" in ns_config.mailboxes

    def test_remove_mailbox(self, temp_config_dir):
        ns_config = NamespaceConfig(ns="abc123", secret="ns-secret")
        ns_config.add_mailbox(id="mb1", secret="s1")
        ns_config.add_mailbox(id="mb2", secret="s2")

        assert ns_config.remove_mailbox("mb1") is True
        assert "mb1" not in ns_config.mailboxes
        assert "mb2" in ns_config.mailboxes

        assert ns_config.remove_mailbox("nonexistent") is False

    def test_save_and_load_with_mailboxes(self, temp_config_dir):
        ns_config = NamespaceConfig(ns="abc123", secret="ns-secret")
        ns_config.add_mailbox(id="mb1", secret="s1", display_name="Agent 1")
        ns_config.add_mailbox(id="mb2", secret="s2", display_name="Agent 2")
        ns_config.save()

        loaded = NamespaceConfig.load("abc123")
        assert loaded is not None
        assert len(loaded.mailboxes) == 2
        assert loaded.mailboxes["mb1"].secret == "s1"
        assert loaded.mailboxes["mb1"].display_name == "Agent 1"
        assert loaded.mailboxes["mb2"].secret == "s2"

    def test_delete(self, temp_config_dir):
        ns_config = NamespaceConfig(ns="abc123", secret="ns-secret")
        ns_config.save()

        assert ns_config.get_path().exists()
        assert ns_config.delete() is True
        assert not ns_config.get_path().exists()

        # Deleting again returns False
        assert ns_config.delete() is False


class TestMailboxConfig:
    def test_to_dict(self):
        mb = MailboxConfig(
            id="mb1",
            secret="secret123",
            display_name="Test Mailbox",
            metadata={"role": "worker"},
            created_at="2024-01-15T10:00:00Z",
        )

        data = mb.to_dict()
        assert data["secret"] == "secret123"
        assert data["display_name"] == "Test Mailbox"
        assert data["metadata"] == {"role": "worker"}
        assert data["created_at"] == "2024-01-15T10:00:00Z"
        assert "id" not in data  # ID is the key, not in value

    def test_from_dict(self):
        data = {
            "secret": "secret123",
            "display_name": "Test Mailbox",
            "metadata": {"role": "worker"},
            "created_at": "2024-01-15T10:00:00Z",
        }

        mb = MailboxConfig.from_dict("mb1", data)
        assert mb.id == "mb1"
        assert mb.secret == "secret123"
        assert mb.display_name == "Test Mailbox"
        assert mb.metadata == {"role": "worker"}


class TestSource:
    """Tests for Source dataclass."""

    def test_remote_source(self):
        """Create a remote source."""
        source = Source(
            name="work",
            type="remote",
            url="https://work.deaddrop.io",
            bearer_token="secret123",
        )

        assert source.name == "work"
        assert source.type == "remote"
        assert source.url == "https://work.deaddrop.io"
        assert source.bearer_token == "secret123"

    def test_local_source(self):
        """Create a local source."""
        source = Source(
            name="dev",
            type="local",
            path="/home/user/project/.deaddrop",
        )

        assert source.name == "dev"
        assert source.type == "local"
        assert source.path == "/home/user/project/.deaddrop"

    def test_source_to_dict(self):
        """Source serializes to dict."""
        source = Source(name="test", type="remote", url="https://example.com")
        data = source.to_dict()

        assert data["name"] == "test"
        assert data["type"] == "remote"
        assert data["url"] == "https://example.com"

    def test_source_from_dict(self):
        """Source deserializes from dict."""
        data = {
            "name": "prod",
            "type": "remote",
            "url": "https://prod.example.com",
            "bearer_token": "token123",
        }
        source = Source.from_dict(data)

        assert source.name == "prod"
        assert source.type == "remote"
        assert source.url == "https://prod.example.com"
        assert source.bearer_token == "token123"


class TestGlobalConfigSources:
    """Tests for GlobalConfig source management."""

    def test_add_source(self):
        """Add a source to config."""
        cfg = GlobalConfig()
        source = Source(name="test", type="remote", url="https://example.com")

        cfg.add_source(source)

        assert len(cfg.sources) == 1
        assert cfg.sources[0].name == "test"

    def test_add_source_replaces_existing(self):
        """Adding a source with same name replaces it."""
        cfg = GlobalConfig()
        cfg.add_source(Source(name="test", type="remote", url="https://old.com"))
        cfg.add_source(Source(name="test", type="remote", url="https://new.com"))

        assert len(cfg.sources) == 1
        assert cfg.sources[0].url == "https://new.com"

    def test_get_source(self):
        """Get a source by name."""
        cfg = GlobalConfig()
        cfg.add_source(Source(name="alpha", type="remote", url="https://alpha.com"))
        cfg.add_source(Source(name="beta", type="local", path="/path/to/beta"))

        alpha = cfg.get_source("alpha")
        beta = cfg.get_source("beta")
        none = cfg.get_source("gamma")

        assert alpha is not None
        assert alpha.url == "https://alpha.com"
        assert beta is not None
        assert beta.path == "/path/to/beta"
        assert none is None

    def test_remove_source(self):
        """Remove a source by name."""
        cfg = GlobalConfig()
        cfg.add_source(Source(name="test", type="remote", url="https://example.com"))

        result = cfg.remove_source("test")

        assert result is True
        assert len(cfg.sources) == 0

    def test_remove_source_not_found(self):
        """Remove returns False if source not found."""
        cfg = GlobalConfig()

        result = cfg.remove_source("nonexistent")

        assert result is False

    def test_remove_source_clears_default(self):
        """Removing the default source clears the default."""
        cfg = GlobalConfig()
        cfg.add_source(Source(name="test", type="remote", url="https://example.com"))
        cfg.default_source = "test"

        cfg.remove_source("test")

        assert cfg.default_source is None

    def test_get_default_source(self):
        """Get default source returns the source if set."""
        cfg = GlobalConfig()
        cfg.add_source(Source(name="main", type="remote", url="https://main.com"))
        cfg.default_source = "main"

        default = cfg.get_default_source()

        assert default is not None
        assert default.name == "main"

    def test_get_default_source_none(self):
        """Get default source returns None if not set."""
        cfg = GlobalConfig()

        default = cfg.get_default_source()

        assert default is None

    def test_save_and_load_with_sources(self, temp_config_dir):
        """Sources are persisted to config file."""
        cfg = GlobalConfig()
        cfg.add_source(Source(name="work", type="remote", url="https://work.io"))
        cfg.add_source(Source(name="dev", type="local", path="/dev/.deaddrop"))
        cfg.default_source = "work"
        cfg.save()

        loaded = GlobalConfig.load()
        assert len(loaded.sources) == 2
        work = loaded.get_source("work")
        assert work is not None
        assert work.url == "https://work.io"
        dev = loaded.get_source("dev")
        assert dev is not None
        assert dev.path == "/dev/.deaddrop"
        assert loaded.default_source == "work"
