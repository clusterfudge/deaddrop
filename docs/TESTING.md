# Testing with Deaddrop

Deaddrop provides pytest fixtures and utilities for testing agent communication.

## Quick Start

### Using Fixtures

Add to your `conftest.py`:

```python
pytest_plugins = ["deadrop.testing"]
```

Or import specific fixtures:

```python
from deadrop.testing import deaddrop, deaddrop_with_identities
```

### Basic Test

```python
def test_agent_messaging(deaddrop):
    """Test with fresh in-memory client."""
    ns = deaddrop.create_namespace("Test")
    alice = deaddrop.create_identity(ns["ns"], "Alice")
    bob = deaddrop.create_identity(ns["ns"], "Bob")
    
    deaddrop.send_message(ns["ns"], alice["secret"], bob["id"], "Hello!")
    
    messages = deaddrop.get_inbox(ns["ns"], bob["id"], bob["secret"])
    assert len(messages) == 1
    assert messages[0]["body"] == "Hello!"
```

## Available Fixtures

### `deaddrop`

Fresh in-memory Deaddrop client. No cleanup needed.

```python
def test_something(deaddrop):
    ns = deaddrop.create_namespace("Test")
    # ... test code ...
```

### `deaddrop_local`

File-backed local client using `tmp_path`. Useful for testing persistence.

```python
def test_persistence(deaddrop_local, tmp_path):
    ns = deaddrop_local.create_namespace("Test")
    deaddrop_local.close()
    
    # Reopen and verify
    from deadrop import Deaddrop
    client2 = Deaddrop.local(tmp_path / ".deaddrop")
    assert client2.get_namespace(ns["ns"]) is not None
```

### `deaddrop_with_namespace`

Client with a pre-created namespace.

```python
def test_with_namespace(deaddrop_with_namespace):
    client, ns = deaddrop_with_namespace
    alice = client.create_identity(ns["ns"], "Alice")
    # ...
```

### `deaddrop_with_identities`

Client with namespace and two identities (Alice and Bob).

```python
def test_messaging(deaddrop_with_identities):
    client, ns, alice, bob = deaddrop_with_identities
    
    client.send_message(ns["ns"], alice["secret"], bob["id"], "Hi!")
    messages = client.get_inbox(ns["ns"], bob["id"], bob["secret"])
    assert len(messages) == 1
```

### `deaddrop_quick_setup`

Client with namespace and three identities (Alice, Bob, Charlie).

```python
def test_multi_agent(deaddrop_quick_setup):
    client, setup = deaddrop_quick_setup
    ns = setup["namespace"]["ns"]
    alice = setup["identities"]["Alice"]
    bob = setup["identities"]["Bob"]
    charlie = setup["identities"]["Charlie"]
    
    # Alice broadcasts to Bob and Charlie
    client.send_message(ns, alice["secret"], bob["id"], "Team meeting!")
    client.send_message(ns, alice["secret"], charlie["id"], "Team meeting!")
```

### `deaddrop_any_backend`

Parametrized fixture that runs tests against both `in_memory` and `local` backends.

```python
def test_works_everywhere(deaddrop_any_backend):
    """This test runs twice - once per backend."""
    client = deaddrop_any_backend
    ns = client.create_namespace("Test")
    assert ns["ns"] is not None
```

## Convenience Methods

### `quick_setup`

Create namespace and identities in one call:

```python
def test_with_quick_setup(deaddrop):
    setup = deaddrop.quick_setup(
        namespace_name="Test",
        identities=["Alice", "Bob", "Charlie"]
    )
    
    ns = setup["namespace"]["ns"]
    alice = setup["identities"]["Alice"]
    bob = setup["identities"]["Bob"]
    
    deaddrop.send_message(ns, alice["secret"], bob["id"], "Hello!")
```

### `send_and_receive`

Send a message and immediately receive it:

```python
def test_round_trip(deaddrop):
    setup = deaddrop.quick_setup("Test", ["Alice", "Bob"])
    
    sent, received = deaddrop.send_and_receive(
        ns=setup["namespace"]["ns"],
        from_identity=setup["identities"]["Alice"],
        to_identity=setup["identities"]["Bob"],
        body="Test message"
    )
    
    assert sent["mid"] == received["mid"]
    assert received["body"] == "Test message"
```

## Utility Functions

### `make_test_setup`

Create a test setup for custom fixtures:

```python
from deadrop.testing import make_test_setup

@pytest.fixture
def my_agent_setup(deaddrop):
    return make_test_setup(
        deaddrop,
        namespace_name="Agents",
        identities=["Coordinator", "Worker1", "Worker2"]
    )
```

### `send_test_messages`

Send multiple test messages:

```python
from deadrop.testing import send_test_messages

def test_message_processing(deaddrop):
    setup = deaddrop.quick_setup("Test", ["Sender", "Receiver"])
    
    messages = send_test_messages(
        deaddrop,
        ns=setup["namespace"]["ns"],
        from_identity=setup["identities"]["Sender"],
        to_identity=setup["identities"]["Receiver"],
        count=10,
        body_prefix="Task"
    )
    
    assert len(messages) == 10
```

## Backend Parity Testing

Test that your code works identically with local and remote backends:

```python
@pytest.fixture(params=["in_memory", "local", "remote"])
def any_deaddrop(request, tmp_path, live_server):
    """Test against all backends."""
    from deadrop import Deaddrop
    
    if request.param == "in_memory":
        client = Deaddrop.in_memory()
    elif request.param == "local":
        client = Deaddrop.create_local(tmp_path / ".deaddrop")
    else:
        client = Deaddrop.remote(url=live_server.url)
    
    yield client
    client.close()

def test_messaging_works_everywhere(any_deaddrop):
    """Runs 3x with different backends."""
    setup = any_deaddrop.quick_setup("Test", ["Alice", "Bob"])
    # ... test code that should work identically ...
```

## Best Practices

### Use In-Memory for Speed

```python
# Fastest - no file I/O
def test_fast(deaddrop):  # Uses in_memory by default
    pass
```

### Context Managers for Explicit Lifecycle

```python
from deadrop import Deaddrop

def test_explicit():
    with Deaddrop.in_memory() as client:
        ns = client.create_namespace("Test")
        # ... test code ...
    # Automatically cleaned up
```

### Test Multiple Agents

```python
def test_multi_agent_workflow(deaddrop):
    setup = deaddrop.quick_setup("Swarm", [
        "Coordinator",
        "Worker1", "Worker2", "Worker3"
    ])
    
    ns = setup["namespace"]["ns"]
    coord = setup["identities"]["Coordinator"]
    workers = [setup["identities"][f"Worker{i}"] for i in range(1, 4)]
    
    # Coordinator sends tasks to all workers
    for i, worker in enumerate(workers):
        deaddrop.send_message(ns, coord["secret"], worker["id"], f"Task {i}")
    
    # Each worker receives one task
    for worker in workers:
        messages = deaddrop.get_inbox(ns, worker["id"], worker["secret"])
        assert len(messages) == 1
```

### Isolate Tests

Each test gets a fresh client, so no cleanup needed:

```python
def test_one(deaddrop):
    deaddrop.create_namespace("Test")
    # This namespace is gone after the test

def test_two(deaddrop):
    namespaces = deaddrop.list_namespaces()
    assert len(namespaces) == 0  # Fresh client!
```
