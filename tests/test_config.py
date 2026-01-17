"""Tests for deadrop configuration management."""

import tempfile
from pathlib import Path

import pytest

from deadrop.config import (
    GlobalConfig,
    MailboxConfig,
    NamespaceConfig,
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
