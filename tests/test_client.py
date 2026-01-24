"""Tests for the unified Deaddrop client."""

import pytest

from deadrop.client import Deaddrop
from deadrop.options import DeaddropOptions
from deadrop.discovery import DeaddropNotFound


class TestDeaddropFactoryMethods:
    """Test Deaddrop factory methods."""

    def test_in_memory(self):
        """Should create in-memory backend."""
        client = Deaddrop.in_memory()
        assert client.backend == "in_memory"
        assert client.location == ":memory:"

    def test_local_with_path(self, tmp_path):
        """Should create local backend with explicit path."""
        path = tmp_path / ".deaddrop"
        path.mkdir()
        # Initialize the db
        from deadrop.backends import LocalBackend

        LocalBackend.create(path=path)

        client = Deaddrop.local(path=path)
        assert client.backend == "local"
        assert str(path) in client.location

    def test_local_raises_if_not_found(self, tmp_path, monkeypatch):
        """Should raise if local .deaddrop not found."""
        monkeypatch.chdir(tmp_path)
        with pytest.raises(DeaddropNotFound):
            Deaddrop.local()

    def test_create_local(self, tmp_path):
        """Should create new .deaddrop directory."""
        path = tmp_path / ".deaddrop"
        client = Deaddrop.create_local(path=path)

        assert client.backend == "local"
        assert path.exists()
        assert (path / "config.yaml").exists()
        assert (path / "data.db").exists()

    def test_create_local_default_path(self, tmp_path, monkeypatch):
        """Should create .deaddrop in cwd if not in git."""
        monkeypatch.chdir(tmp_path)
        client = Deaddrop.create_local()

        assert client.backend == "local"
        assert (tmp_path / ".deaddrop").exists()

    def test_create_local_git_root(self, tmp_path, monkeypatch):
        """Should create .deaddrop in git root."""
        # Create git repo
        git_dir = tmp_path / ".git"
        git_dir.mkdir()

        # Change to subdirectory
        subdir = tmp_path / "src"
        subdir.mkdir()
        monkeypatch.chdir(subdir)

        Deaddrop.create_local()

        # Should be at git root, not subdir
        assert (tmp_path / ".deaddrop").exists()
        assert not (subdir / ".deaddrop").exists()

    def test_discover(self, tmp_path, monkeypatch):
        """Should discover existing .deaddrop."""
        # Create .deaddrop
        deaddrop = tmp_path / ".deaddrop"
        Deaddrop.create_local(path=deaddrop)

        monkeypatch.chdir(tmp_path)
        client = Deaddrop.discover()

        assert client.backend == "local"

    def test_remote(self):
        """Should create remote backend."""
        client = Deaddrop.remote(
            url="https://deaddrop.example.com",
            bearer_token="test_token",
        )
        assert client.backend == "remote"
        assert "deaddrop.example.com" in client.location


class TestDeaddropOptions:
    """Test Deaddrop with DeaddropOptions."""

    def test_with_in_memory_option(self):
        """Should work with in_memory option."""
        client = Deaddrop(DeaddropOptions(in_memory=True))
        assert client.backend == "in_memory"

    def test_with_path_option(self, tmp_path):
        """Should work with path option."""
        path = tmp_path / ".deaddrop"
        Deaddrop.create_local(path=path)

        client = Deaddrop(DeaddropOptions(path=path))
        assert client.backend == "local"

    def test_with_url_option(self):
        """Should work with url option."""
        client = Deaddrop(DeaddropOptions(url="https://example.com"))
        assert client.backend == "remote"


class TestDeaddropOperations:
    """Test Deaddrop client operations."""

    @pytest.fixture
    def client(self):
        """In-memory client for testing."""
        return Deaddrop.in_memory()

    def test_create_namespace(self, client):
        """Should create namespace."""
        ns = client.create_namespace(
            display_name="Test",
            ttl_hours=48,
        )

        assert ns["ns"] is not None
        assert ns["secret"] is not None
        assert ns["metadata"]["display_name"] == "Test"
        assert ns["ttl_hours"] == 48

    def test_list_namespaces(self, client):
        """Should list namespaces."""
        client.create_namespace(display_name="NS1")
        client.create_namespace(display_name="NS2")

        namespaces = client.list_namespaces()
        assert len(namespaces) == 2

    def test_get_namespace(self, client):
        """Should get namespace by ID."""
        ns = client.create_namespace(display_name="Test")
        fetched = client.get_namespace(ns["ns"])

        assert fetched is not None
        assert fetched["ns"] == ns["ns"]

    def test_delete_namespace(self, client):
        """Should delete namespace."""
        ns = client.create_namespace(display_name="Test")
        result = client.delete_namespace(ns["ns"])

        assert result is True
        assert client.get_namespace(ns["ns"]) is None

    def test_create_identity(self, client):
        """Should create identity."""
        ns = client.create_namespace(display_name="Test")
        identity = client.create_identity(
            ns["ns"],
            display_name="Alice",
        )

        assert identity["id"] is not None
        assert identity["secret"] is not None

    def test_list_identities(self, client):
        """Should list identities."""
        ns = client.create_namespace(display_name="Test")
        client.create_identity(ns["ns"], display_name="Alice")
        client.create_identity(ns["ns"], display_name="Bob")

        identities = client.list_identities(ns["ns"])
        assert len(identities) == 2

    def test_send_and_receive_message(self, client):
        """Should send and receive messages."""
        ns = client.create_namespace(display_name="Test")
        alice = client.create_identity(ns["ns"], display_name="Alice")
        bob = client.create_identity(ns["ns"], display_name="Bob")

        msg = client.send_message(
            ns=ns["ns"],
            from_secret=alice["secret"],
            to_id=bob["id"],
            body="Hello!",
        )

        messages = client.get_inbox(
            ns=ns["ns"],
            identity_id=bob["id"],
            secret=bob["secret"],
        )

        assert len(messages) == 1
        assert messages[0]["mid"] == msg["mid"]
        assert messages[0]["body"] == "Hello!"

    def test_delete_message(self, client):
        """Should delete message."""
        ns = client.create_namespace(display_name="Test")
        alice = client.create_identity(ns["ns"], display_name="Alice")
        bob = client.create_identity(ns["ns"], display_name="Bob")

        msg = client.send_message(ns["ns"], alice["secret"], bob["id"], "Test")
        result = client.delete_message(ns["ns"], bob["id"], bob["secret"], msg["mid"])

        assert result is True
        messages = client.get_inbox(ns["ns"], bob["id"], bob["secret"])
        assert len(messages) == 0

    def test_archive_message(self, client):
        """Should archive and retrieve archived messages."""
        ns = client.create_namespace(display_name="Test")
        alice = client.create_identity(ns["ns"], display_name="Alice")
        bob = client.create_identity(ns["ns"], display_name="Bob")

        msg = client.send_message(ns["ns"], alice["secret"], bob["id"], "Test")
        # Read it first
        client.get_inbox(ns["ns"], bob["id"], bob["secret"])

        # Archive
        result = client.archive_message(ns["ns"], bob["id"], bob["secret"], msg["mid"])
        assert result is True

        # Not in regular inbox
        messages = client.get_inbox(ns["ns"], bob["id"], bob["secret"])
        assert len(messages) == 0

        # In archived
        archived = client.get_archived_messages(ns["ns"], bob["id"], bob["secret"])
        assert len(archived) == 1


class TestDeaddropConvenienceMethods:
    """Test Deaddrop convenience methods."""

    @pytest.fixture
    def client(self):
        return Deaddrop.in_memory()

    def test_quick_setup(self, client):
        """Should create namespace and identities in one call."""
        setup = client.quick_setup(
            namespace_name="Test",
            identities=["Alice", "Bob", "Charlie"],
        )

        assert "namespace" in setup
        assert setup["namespace"]["ns"] is not None
        assert setup["namespace"]["secret"] is not None

        assert "identities" in setup
        assert "Alice" in setup["identities"]
        assert "Bob" in setup["identities"]
        assert "Charlie" in setup["identities"]

        for name, identity in setup["identities"].items():
            assert identity["id"] is not None
            assert identity["secret"] is not None

    def test_quick_setup_can_send_messages(self, client):
        """Should be able to send messages with quick_setup result."""
        setup = client.quick_setup("Test", ["Alice", "Bob"])
        ns = setup["namespace"]["ns"]
        alice = setup["identities"]["Alice"]
        bob = setup["identities"]["Bob"]

        client.send_message(ns, alice["secret"], bob["id"], "Hello!")
        messages = client.get_inbox(ns, bob["id"], bob["secret"])

        assert len(messages) == 1
        assert messages[0]["body"] == "Hello!"

    def test_send_and_receive(self, client):
        """Should send and receive in one call."""
        setup = client.quick_setup("Test", ["Alice", "Bob"])
        ns = setup["namespace"]["ns"]

        sent, received = client.send_and_receive(
            ns=ns,
            from_identity=setup["identities"]["Alice"],
            to_identity=setup["identities"]["Bob"],
            body="Test message",
        )

        assert sent["mid"] == received["mid"]
        assert received["body"] == "Test message"


class TestDeaddropContextManager:
    """Test Deaddrop as context manager."""

    def test_context_manager(self):
        """Should work as context manager."""
        with Deaddrop.in_memory() as client:
            ns = client.create_namespace(display_name="Test")
            assert ns["ns"] is not None
        # Connection closed after exiting context

    def test_explicit_close(self):
        """Should support explicit close."""
        client = Deaddrop.in_memory()
        ns = client.create_namespace(display_name="Test")
        assert ns["ns"] is not None
        client.close()
