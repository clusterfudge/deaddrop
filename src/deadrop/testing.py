"""Pytest fixtures for testing with Deaddrop.

Usage in conftest.py:
    pytest_plugins = ["deadrop.testing"]

Or import specific fixtures:
    from deadrop.testing import deaddrop, deaddrop_with_namespace

Available fixtures:
    - deaddrop: Fresh in-memory Deaddrop client
    - deaddrop_local: File-backed local Deaddrop (uses tmp_path)
    - deaddrop_with_namespace: Client with pre-created namespace
    - deaddrop_with_identities: Client with namespace + Alice + Bob
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Generator

import pytest

from .client import Deaddrop

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def deaddrop() -> Generator[Deaddrop, None, None]:
    """Fresh in-memory Deaddrop client.

    No cleanup needed - all data is ephemeral.

    Example:
        def test_something(deaddrop):
            ns = deaddrop.create_namespace("Test")
            alice = deaddrop.create_identity(ns["ns"], "Alice")
            ...
    """
    client = Deaddrop.in_memory()
    yield client
    client.close()


@pytest.fixture
def deaddrop_local(tmp_path: "Path") -> Generator[Deaddrop, None, None]:
    """File-backed local Deaddrop client.

    Creates a .deaddrop directory in tmp_path.
    Useful for testing persistence behavior.

    Example:
        def test_persistence(deaddrop_local, tmp_path):
            ns = deaddrop_local.create_namespace("Test")
            deaddrop_local.close()

            # Reopen and verify
            client2 = Deaddrop.local(tmp_path / ".deaddrop")
            assert client2.get_namespace(ns["ns"]) is not None
    """
    client = Deaddrop.create_local(path=tmp_path / ".deaddrop")
    yield client
    client.close()


@pytest.fixture
def deaddrop_with_namespace(
    deaddrop: Deaddrop,
) -> Generator[tuple[Deaddrop, dict[str, Any]], None, None]:
    """Deaddrop client with a pre-created namespace.

    Returns:
        Tuple of (client, namespace_dict)

    Example:
        def test_with_namespace(deaddrop_with_namespace):
            client, ns = deaddrop_with_namespace
            alice = client.create_identity(ns["ns"], "Alice")
            ...
    """
    ns = deaddrop.create_namespace(display_name="Test Namespace")
    yield deaddrop, ns


@pytest.fixture
def deaddrop_with_identities(
    deaddrop: Deaddrop,
) -> Generator[tuple[Deaddrop, dict[str, Any], dict[str, Any], dict[str, Any]], None, None]:
    """Deaddrop client with namespace and two identities (Alice and Bob).

    Returns:
        Tuple of (client, namespace, alice, bob)

    Example:
        def test_messaging(deaddrop_with_identities):
            client, ns, alice, bob = deaddrop_with_identities
            client.send_message(ns["ns"], alice["secret"], bob["id"], "Hi!")
            messages = client.get_inbox(ns["ns"], bob["id"], bob["secret"])
            assert len(messages) == 1
    """
    ns = deaddrop.create_namespace(display_name="Test Namespace")
    alice = deaddrop.create_identity(ns["ns"], display_name="Alice")
    bob = deaddrop.create_identity(ns["ns"], display_name="Bob")
    yield deaddrop, ns, alice, bob


@pytest.fixture
def deaddrop_quick_setup(
    deaddrop: Deaddrop,
) -> Generator[tuple[Deaddrop, dict[str, Any]], None, None]:
    """Deaddrop client with quick_setup result.

    Creates namespace with Alice, Bob, and Charlie.

    Returns:
        Tuple of (client, setup_dict)

    Example:
        def test_multi_agent(deaddrop_quick_setup):
            client, setup = deaddrop_quick_setup
            ns = setup["namespace"]["ns"]
            alice = setup["identities"]["Alice"]
            bob = setup["identities"]["Bob"]
            charlie = setup["identities"]["Charlie"]

            client.send_message(ns, alice["secret"], bob["id"], "Hello Bob!")
            client.send_message(ns, alice["secret"], charlie["id"], "Hello Charlie!")
    """
    setup = deaddrop.quick_setup(
        namespace_name="Test",
        identities=["Alice", "Bob", "Charlie"],
    )
    yield deaddrop, setup


# --- Parametrized Fixtures for Backend Parity Testing ---


def _create_backend(request: Any, tmp_path: "Path") -> Deaddrop:
    """Helper to create backends based on parameter."""
    if request.param == "in_memory":
        return Deaddrop.in_memory()
    elif request.param == "local":
        return Deaddrop.create_local(path=tmp_path / ".deaddrop")
    else:
        raise ValueError(f"Unknown backend type: {request.param}")


@pytest.fixture(params=["in_memory", "local"])
def deaddrop_any_backend(
    request: Any,
    tmp_path: "Path",
) -> Generator[Deaddrop, None, None]:
    """Parametrized fixture that runs tests against multiple backends.

    Use this to verify behavior is consistent across backends.

    Example:
        def test_works_everywhere(deaddrop_any_backend):
            client = deaddrop_any_backend
            ns = client.create_namespace("Test")
            assert ns["ns"] is not None
            # This test runs twice: once with in_memory, once with local
    """
    client = _create_backend(request, tmp_path)
    yield client
    client.close()


# --- Utility Functions ---


def make_test_setup(
    client: Deaddrop,
    namespace_name: str = "Test",
    identities: list[str] | None = None,
) -> dict[str, Any]:
    """Create a test setup with namespace and identities.

    Utility function for custom fixtures.

    Args:
        client: Deaddrop client
        namespace_name: Name for the namespace
        identities: List of identity names (default: ["Alice", "Bob"])

    Returns:
        dict with namespace and identities
    """
    if identities is None:
        identities = ["Alice", "Bob"]
    return client.quick_setup(namespace_name, identities)


def send_test_messages(
    client: Deaddrop,
    ns: str,
    from_identity: dict[str, Any],
    to_identity: dict[str, Any],
    count: int = 5,
    body_prefix: str = "Message",
) -> list[dict[str, Any]]:
    """Send multiple test messages.

    Utility function for testing message operations.

    Args:
        client: Deaddrop client
        ns: Namespace ID
        from_identity: Sender identity dict
        to_identity: Recipient identity dict
        count: Number of messages to send
        body_prefix: Prefix for message bodies

    Returns:
        List of sent message dicts
    """
    messages = []
    for i in range(count):
        msg = client.send_message(
            ns=ns,
            from_secret=from_identity["secret"],
            to_id=to_identity["id"],
            body=f"{body_prefix} {i + 1}",
        )
        messages.append(msg)
    return messages
