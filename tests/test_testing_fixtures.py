"""Tests for deadrop.testing fixtures."""

from deadrop import Deaddrop

# Import utility functions (not fixtures)
from deadrop.testing import (
    make_test_setup,
    send_test_messages,
)

# Register the fixtures from deadrop.testing
pytest_plugins = ["deadrop.testing"]


class TestDeaddropFixture:
    """Test the basic deaddrop fixture."""

    def test_creates_in_memory_client(self, deaddrop):
        """Should create in-memory client."""
        assert deaddrop.backend == "in_memory"

    def test_can_create_namespace(self, deaddrop):
        """Should be able to create namespace."""
        ns = deaddrop.create_namespace("Test")
        assert ns["ns"] is not None

    def test_fresh_each_test(self, deaddrop):
        """Should be fresh for each test (no leftover data)."""
        namespaces = deaddrop.list_namespaces()
        assert len(namespaces) == 0


class TestDeaddropLocalFixture:
    """Test the deaddrop_local fixture."""

    def test_creates_local_client(self, deaddrop_local):
        """Should create local file-backed client."""
        assert deaddrop_local.backend == "local"

    def test_creates_deaddrop_directory(self, deaddrop_local, tmp_path):
        """Should create .deaddrop directory."""
        assert (tmp_path / ".deaddrop").exists()
        assert (tmp_path / ".deaddrop" / "data.db").exists()

    def test_persists_data(self, deaddrop_local, tmp_path):
        """Data should persist to disk."""
        ns = deaddrop_local.create_namespace("Test")
        deaddrop_local.close()

        # Reopen and verify
        client2 = Deaddrop.local(tmp_path / ".deaddrop")
        fetched = client2.get_namespace(ns["ns"])
        assert fetched is not None
        client2.close()


class TestDeaddropWithNamespaceFixture:
    """Test the deaddrop_with_namespace fixture."""

    def test_returns_tuple(self, deaddrop_with_namespace):
        """Should return (client, namespace) tuple."""
        client, ns = deaddrop_with_namespace
        assert isinstance(client, Deaddrop)
        assert isinstance(ns, dict)

    def test_namespace_exists(self, deaddrop_with_namespace):
        """Namespace should already exist."""
        client, ns = deaddrop_with_namespace
        assert ns["ns"] is not None
        assert ns["secret"] is not None

        fetched = client.get_namespace(ns["ns"])
        assert fetched is not None


class TestDeaddropWithIdentitiesFixture:
    """Test the deaddrop_with_identities fixture."""

    def test_returns_four_values(self, deaddrop_with_identities):
        """Should return (client, ns, alice, bob)."""
        client, ns, alice, bob = deaddrop_with_identities
        assert isinstance(client, Deaddrop)
        assert ns["ns"] is not None
        assert alice["id"] is not None
        assert bob["id"] is not None

    def test_can_send_messages(self, deaddrop_with_identities):
        """Should be able to send messages immediately."""
        client, ns, alice, bob = deaddrop_with_identities

        msg = client.send_message(ns["ns"], alice["secret"], bob["id"], "Hello!")
        assert msg["mid"] is not None

        messages = client.get_inbox(ns["ns"], bob["id"], bob["secret"])
        assert len(messages) == 1


class TestDeaddropQuickSetupFixture:
    """Test the deaddrop_quick_setup fixture."""

    def test_has_three_identities(self, deaddrop_quick_setup):
        """Should have Alice, Bob, and Charlie."""
        client, setup = deaddrop_quick_setup

        assert "Alice" in setup["identities"]
        assert "Bob" in setup["identities"]
        assert "Charlie" in setup["identities"]

    def test_can_send_to_all(self, deaddrop_quick_setup):
        """Should be able to send between any identities."""
        client, setup = deaddrop_quick_setup
        ns = setup["namespace"]["ns"]
        alice = setup["identities"]["Alice"]
        bob = setup["identities"]["Bob"]
        charlie = setup["identities"]["Charlie"]

        # Alice sends to Bob
        client.send_message(ns, alice["secret"], bob["id"], "Hi Bob!")

        # Alice sends to Charlie
        client.send_message(ns, alice["secret"], charlie["id"], "Hi Charlie!")

        # Bob sends to Charlie
        client.send_message(ns, bob["secret"], charlie["id"], "Hi from Bob!")

        # Charlie should have 2 messages
        messages = client.get_inbox(ns, charlie["id"], charlie["secret"])
        assert len(messages) == 2


class TestDeaddropAnyBackendFixture:
    """Test the parametrized deaddrop_any_backend fixture."""

    def test_works_with_both_backends(self, deaddrop_any_backend):
        """Test runs with both in_memory and local backends."""
        assert deaddrop_any_backend.backend in ("in_memory", "local")

    def test_full_workflow(self, deaddrop_any_backend):
        """Full workflow should work identically on all backends."""
        client = deaddrop_any_backend

        ns = client.create_namespace("Test")
        alice = client.create_identity(ns["ns"], "Alice")
        bob = client.create_identity(ns["ns"], "Bob")

        msg = client.send_message(ns["ns"], alice["secret"], bob["id"], "Hello!")
        messages = client.get_inbox(ns["ns"], bob["id"], bob["secret"])

        assert len(messages) == 1
        assert messages[0]["mid"] == msg["mid"]


class TestUtilityFunctions:
    """Test utility functions."""

    def test_make_test_setup(self, deaddrop):
        """Should create setup with defaults."""
        setup = make_test_setup(deaddrop)

        assert "namespace" in setup
        assert "Alice" in setup["identities"]
        assert "Bob" in setup["identities"]

    def test_make_test_setup_custom(self, deaddrop):
        """Should create setup with custom identities."""
        setup = make_test_setup(
            deaddrop,
            namespace_name="Custom",
            identities=["Agent1", "Agent2", "Agent3"],
        )

        assert "Agent1" in setup["identities"]
        assert "Agent2" in setup["identities"]
        assert "Agent3" in setup["identities"]

    def test_send_test_messages(self, deaddrop):
        """Should send multiple test messages."""
        setup = make_test_setup(deaddrop)
        ns = setup["namespace"]["ns"]
        alice = setup["identities"]["Alice"]
        bob = setup["identities"]["Bob"]

        messages = send_test_messages(
            deaddrop,
            ns,
            alice,
            bob,
            count=3,
        )

        assert len(messages) == 3

        inbox = deaddrop.get_inbox(ns, bob["id"], bob["secret"])
        assert len(inbox) == 3
