"""Tests for backend implementations."""

import pytest

from deadrop.backends import (
    BackendInfo,
    LocalBackend,
    InMemoryBackend,
    LocalConfig,
)


class TestLocalConfig:
    """Test LocalConfig persistence."""

    def test_load_empty(self, tmp_path):
        """Should return empty config if file doesn't exist."""
        config = LocalConfig.load(tmp_path)
        assert config.namespaces == {}

    def test_save_and_load(self, tmp_path):
        """Should round-trip config to YAML."""
        config = LocalConfig()
        config.namespaces["ns123"] = {
            "secret": "sk_test",
            "display_name": "Test",
        }
        config.save(tmp_path)

        loaded = LocalConfig.load(tmp_path)
        assert loaded.namespaces["ns123"]["secret"] == "sk_test"
        assert loaded.namespaces["ns123"]["display_name"] == "Test"


class TestLocalBackend:
    """Test LocalBackend operations."""

    def test_create_new(self, tmp_path):
        """Should create new .deaddrop directory."""
        path = tmp_path / ".deaddrop"
        backend = LocalBackend.create(path=path)

        assert path.exists()
        assert (path / "config.yaml").exists()
        assert (path / "data.db").exists()

        info = backend.get_info()
        assert info.backend_type == "local"
        assert str(path) in info.location

    def test_load_existing(self, tmp_path):
        """Should load existing .deaddrop directory."""
        path = tmp_path / ".deaddrop"

        # Create first
        backend1 = LocalBackend.create(path=path)
        ns = backend1.create_namespace(display_name="Test")
        backend1.close()

        # Load again
        backend2 = LocalBackend(path)
        assert ns["ns"] in backend2.config.namespaces
        backend2.close()

    def test_raises_if_not_found(self, tmp_path):
        """Should raise if .deaddrop doesn't exist."""
        path = tmp_path / ".deaddrop"
        with pytest.raises(FileNotFoundError):
            LocalBackend(path)

    def test_create_namespace(self, tmp_path):
        """Should create namespace and store in config."""
        path = tmp_path / ".deaddrop"
        backend = LocalBackend.create(path=path)

        ns = backend.create_namespace(
            display_name="Test Project",
            ttl_hours=48,
        )

        assert ns["ns"] is not None
        assert ns["secret"] is not None
        assert ns["metadata"]["display_name"] == "Test Project"
        assert ns["ttl_hours"] == 48

        # Should be in local config
        assert ns["ns"] in backend.config.namespaces
        assert backend.config.namespaces[ns["ns"]]["secret"] == ns["secret"]

        backend.close()

    def test_list_namespaces(self, tmp_path):
        """Should list all namespaces."""
        backend = LocalBackend.create(tmp_path / ".deaddrop")

        backend.create_namespace(display_name="NS1")
        backend.create_namespace(display_name="NS2")

        namespaces = backend.list_namespaces()
        assert len(namespaces) == 2
        backend.close()

    def test_delete_namespace(self, tmp_path):
        """Should delete namespace from DB and config."""
        backend = LocalBackend.create(tmp_path / ".deaddrop")
        ns = backend.create_namespace(display_name="Test")

        result = backend.delete_namespace(ns["ns"])
        assert result is True
        assert ns["ns"] not in backend.config.namespaces
        assert backend.get_namespace(ns["ns"]) is None

        backend.close()

    def test_create_identity(self, tmp_path):
        """Should create identity in namespace."""
        backend = LocalBackend.create(tmp_path / ".deaddrop")
        ns = backend.create_namespace(display_name="Test")

        identity = backend.create_identity(
            ns["ns"],
            display_name="Alice",
        )

        assert identity["id"] is not None
        assert identity["secret"] is not None
        assert identity["metadata"]["display_name"] == "Alice"

        backend.close()

    def test_send_and_receive_message(self, tmp_path):
        """Should send and receive messages."""
        backend = LocalBackend.create(tmp_path / ".deaddrop")
        ns = backend.create_namespace(display_name="Test")
        alice = backend.create_identity(ns["ns"], display_name="Alice")
        bob = backend.create_identity(ns["ns"], display_name="Bob")

        # Send message
        msg = backend.send_message(
            ns=ns["ns"],
            from_secret=alice["secret"],
            to_id=bob["id"],
            body="Hello Bob!",
        )
        assert msg["mid"] is not None
        assert msg["from"] == alice["id"]
        assert msg["to"] == bob["id"]

        # Receive message
        messages = backend.get_inbox(
            ns=ns["ns"],
            identity_id=bob["id"],
            secret=bob["secret"],
        )
        assert len(messages) == 1
        assert messages[0]["body"] == "Hello Bob!"

        backend.close()

    def test_send_requires_valid_secret(self, tmp_path):
        """Should reject send with invalid secret."""
        backend = LocalBackend.create(tmp_path / ".deaddrop")
        ns = backend.create_namespace(display_name="Test")
        bob = backend.create_identity(ns["ns"], display_name="Bob")

        with pytest.raises(PermissionError, match="Invalid sender"):
            backend.send_message(
                ns=ns["ns"],
                from_secret="invalid_secret",
                to_id=bob["id"],
                body="Hello!",
            )

        backend.close()

    def test_inbox_requires_valid_secret(self, tmp_path):
        """Should reject inbox access with invalid secret."""
        backend = LocalBackend.create(tmp_path / ".deaddrop")
        ns = backend.create_namespace(display_name="Test")
        alice = backend.create_identity(ns["ns"], display_name="Alice")

        with pytest.raises(PermissionError, match="Invalid inbox"):
            backend.get_inbox(
                ns=ns["ns"],
                identity_id=alice["id"],
                secret="wrong_secret",
            )

        backend.close()

    def test_archive_message(self, tmp_path):
        """Should archive and retrieve archived messages."""
        backend = LocalBackend.create(tmp_path / ".deaddrop")
        ns = backend.create_namespace(display_name="Test")
        alice = backend.create_identity(ns["ns"], display_name="Alice")
        bob = backend.create_identity(ns["ns"], display_name="Bob")

        # Send and read message
        msg = backend.send_message(ns["ns"], alice["secret"], bob["id"], "Test")
        backend.get_inbox(ns["ns"], bob["id"], bob["secret"])

        # Archive it
        result = backend.archive_message(ns["ns"], bob["id"], bob["secret"], msg["mid"])
        assert result is True

        # Should not appear in regular inbox
        messages = backend.get_inbox(ns["ns"], bob["id"], bob["secret"])
        assert len(messages) == 0

        # Should appear in archived
        archived = backend.get_archived_messages(ns["ns"], bob["id"], bob["secret"])
        assert len(archived) == 1

        backend.close()

    def test_get_namespace_secret(self, tmp_path):
        """Should retrieve namespace secret from config."""
        backend = LocalBackend.create(tmp_path / ".deaddrop")
        ns = backend.create_namespace(display_name="Test")

        secret = backend.get_namespace_secret(ns["ns"])
        assert secret == ns["secret"]

        # Unknown namespace
        assert backend.get_namespace_secret("unknown") is None

        backend.close()


class TestInMemoryBackend:
    """Test InMemoryBackend operations."""

    def test_create(self):
        """Should create in-memory backend."""
        backend = InMemoryBackend()

        info = backend.get_info()
        assert info.backend_type == "in_memory"
        assert info.location == ":memory:"

    def test_no_file_system(self, tmp_path):
        """Should not create any files."""
        backend = InMemoryBackend()
        backend.create_namespace(display_name="Test")

        # No .deaddrop directory should be created
        assert not (tmp_path / ".deaddrop").exists()

    def test_full_workflow(self):
        """Should support full namespace/identity/message workflow."""
        backend = InMemoryBackend()

        # Create namespace
        ns = backend.create_namespace(display_name="Test")
        assert ns["ns"] is not None

        # Create identities
        alice = backend.create_identity(ns["ns"], display_name="Alice")
        bob = backend.create_identity(ns["ns"], display_name="Bob")

        # Send message
        backend.send_message(
            ns=ns["ns"],
            from_secret=alice["secret"],
            to_id=bob["id"],
            body="Hello!",
        )

        # Receive message
        messages = backend.get_inbox(ns["ns"], bob["id"], bob["secret"])
        assert len(messages) == 1
        assert messages[0]["body"] == "Hello!"

    def test_data_lost_on_close(self):
        """Data should be lost when backend is closed."""
        backend = InMemoryBackend()
        ns = backend.create_namespace(display_name="Test")
        backend.close()

        # New backend should be empty
        backend2 = InMemoryBackend()
        assert backend2.get_namespace(ns["ns"]) is None


class TestBackendInterface:
    """Test that backends implement the full interface."""

    @pytest.fixture(params=["local", "in_memory"])
    def backend(self, request, tmp_path):
        """Parametrized fixture for different backend types."""
        if request.param == "local":
            backend = LocalBackend.create(tmp_path / ".deaddrop")
        else:
            backend = InMemoryBackend()

        yield backend
        backend.close()

    def test_get_info(self, backend):
        """All backends should return BackendInfo."""
        info = backend.get_info()
        assert isinstance(info, BackendInfo)
        assert info.backend_type in ("local", "in_memory", "remote")
        assert info.location is not None

    def test_namespace_crud(self, backend):
        """All backends should support namespace CRUD."""
        # Create
        ns = backend.create_namespace(display_name="Test", ttl_hours=24)
        assert ns["ns"] is not None
        assert ns["secret"] is not None

        # Read
        fetched = backend.get_namespace(ns["ns"])
        assert fetched is not None
        assert fetched["ns"] == ns["ns"]

        # List
        namespaces = backend.list_namespaces()
        assert any(n["ns"] == ns["ns"] for n in namespaces)

        # Delete
        result = backend.delete_namespace(ns["ns"])
        assert result is True
        assert backend.get_namespace(ns["ns"]) is None

    def test_identity_crud(self, backend):
        """All backends should support identity CRUD."""
        ns = backend.create_namespace(display_name="Test")

        # Create
        identity = backend.create_identity(ns["ns"], display_name="Alice")
        assert identity["id"] is not None
        assert identity["secret"] is not None

        # Read
        fetched = backend.get_identity(ns["ns"], identity["id"])
        assert fetched is not None
        assert fetched["id"] == identity["id"]

        # List
        identities = backend.list_identities(ns["ns"])
        assert any(i["id"] == identity["id"] for i in identities)

        # Delete
        result = backend.delete_identity(ns["ns"], identity["id"])
        assert result is True
        assert backend.get_identity(ns["ns"], identity["id"]) is None

    def test_messaging(self, backend):
        """All backends should support messaging."""
        ns = backend.create_namespace(display_name="Test")
        alice = backend.create_identity(ns["ns"], display_name="Alice")
        bob = backend.create_identity(ns["ns"], display_name="Bob")

        # Send
        msg = backend.send_message(
            ns=ns["ns"],
            from_secret=alice["secret"],
            to_id=bob["id"],
            body="Hello!",
            content_type="text/plain",
        )
        assert msg["mid"] is not None

        # Receive
        messages = backend.get_inbox(ns["ns"], bob["id"], bob["secret"])
        assert len(messages) == 1
        assert messages[0]["mid"] == msg["mid"]

        # Delete
        result = backend.delete_message(ns["ns"], bob["id"], bob["secret"], msg["mid"])
        assert result is True


class TestBackendLongPolling:
    """Long-poll tests removed — replaced by subscription system."""

    pass


class TestLocalBackendInvites:
    """Tests for local backend invite functionality."""

    def test_create_and_claim_invite(self, tmp_path):
        """Should create and claim an invite successfully."""
        backend = LocalBackend.create(tmp_path / ".deaddrop")

        # Create namespace and identity
        ns = backend.create_namespace(display_name="Test NS")
        ns_id = ns["ns"]
        ns_secret = ns["secret"]

        identity = backend.create_identity(ns_id, display_name="Alice")
        identity_id = identity["id"]
        identity_secret = identity["secret"]

        # Create invite
        invite = backend.create_invite(
            ns=ns_id,
            identity_id=identity_id,
            identity_secret=identity_secret,
            ns_secret=ns_secret,
            display_name="Alice's Invite",
        )

        assert "invite_id" in invite
        assert "invite_url" in invite
        assert invite["invite_url"].startswith("local://")
        assert invite["invite_id"] in invite["invite_url"]

        # Claim invite
        claimed = backend.claim_invite(invite["invite_url"])

        assert claimed["ns"] == ns_id
        assert claimed["identity_id"] == identity_id
        assert claimed["secret"] == identity_secret
        assert claimed["display_name"] == "Alice's Invite"

        backend.close()

    def test_invite_can_only_be_claimed_once(self, tmp_path):
        """Should fail to claim an invite twice."""
        backend = LocalBackend.create(tmp_path / ".deaddrop")

        ns = backend.create_namespace(display_name="Test NS")
        identity = backend.create_identity(ns["ns"], display_name="Alice")

        invite = backend.create_invite(
            ns=ns["ns"],
            identity_id=identity["id"],
            identity_secret=identity["secret"],
            ns_secret=ns["secret"],
        )

        # First claim should succeed
        claimed = backend.claim_invite(invite["invite_url"])
        assert claimed["identity_id"] == identity["id"]

        # Second claim should fail
        with pytest.raises(ValueError, match="not found or already claimed"):
            backend.claim_invite(invite["invite_url"])

        backend.close()

    def test_invite_requires_valid_ns_secret(self, tmp_path):
        """Should reject invite creation with wrong namespace secret."""
        backend = LocalBackend.create(tmp_path / ".deaddrop")

        ns = backend.create_namespace(display_name="Test NS")
        identity = backend.create_identity(ns["ns"], display_name="Alice")

        with pytest.raises(PermissionError, match="Invalid namespace secret"):
            backend.create_invite(
                ns=ns["ns"],
                identity_id=identity["id"],
                identity_secret=identity["secret"],
                ns_secret="wrong_secret",
            )

        backend.close()

    def test_claim_invalid_url_scheme(self, tmp_path):
        """Should reject invite URLs with wrong scheme."""
        backend = LocalBackend.create(tmp_path / ".deaddrop")

        with pytest.raises(ValueError, match="Invalid invite URL scheme"):
            backend.claim_invite("https://example.com/join/abc#key")

        backend.close()

    def test_claim_invalid_url_format(self, tmp_path):
        """Should reject malformed invite URLs."""
        backend = LocalBackend.create(tmp_path / ".deaddrop")

        with pytest.raises(ValueError, match="Invalid invite URL format"):
            backend.claim_invite("local:///some/path/without/join")

        backend.close()

    def test_in_memory_backend_invites(self):
        """InMemoryBackend should also support invites."""
        backend = InMemoryBackend()

        ns = backend.create_namespace(display_name="Test NS")
        identity = backend.create_identity(ns["ns"], display_name="Alice")

        invite = backend.create_invite(
            ns=ns["ns"],
            identity_id=identity["id"],
            identity_secret=identity["secret"],
            ns_secret=ns["secret"],
            display_name="Test Invite",
        )

        claimed = backend.claim_invite(invite["invite_url"])

        assert claimed["ns"] == ns["ns"]
        assert claimed["identity_id"] == identity["id"]
        assert claimed["secret"] == identity["secret"]
