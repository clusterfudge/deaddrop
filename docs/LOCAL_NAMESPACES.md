# Local Namespaces

Deaddrop supports **local, file-system-based namespaces** for offline development, testing, and projects that don't need a remote server.

## Overview

Local namespaces store all data in a `.deaddrop` directory:

```
.deaddrop/
├── config.yaml    # Namespace registry with secrets
└── data.db        # SQLite database (same schema as server)
```

This directory is automatically added to `.gitignore` when created in a git repository.

## Creating Local Namespaces

### Using the CLI

```bash
# Create a local namespace (auto-detects git root or cwd)
deadrop ns create --local --display-name "My Project"

# Create in a specific location
deadrop ns create --local --path /path/to/.deaddrop --display-name "My Project"
```

### Using the Python API

```python
from deadrop import Deaddrop

# Create new local .deaddrop
client = Deaddrop.create_local()

# Or with explicit path
client = Deaddrop.create_local(path="/path/to/.deaddrop")

# Create a namespace
ns = client.create_namespace(display_name="My Project")
print(f"Namespace: {ns['ns']}")
print(f"Secret: {ns['secret']}")
```

## Using Local Namespaces

### Auto-Discovery

Deaddrop auto-discovers local configurations in this order:

1. `$CWD/.deaddrop`
2. `$GIT_ROOT/.deaddrop` (if in a git repository)
3. `~/.config/deadrop/config.yaml` (remote configuration)

```python
from deadrop import Deaddrop

# Auto-discover existing configuration
client = Deaddrop()

# Force local backend (error if not found)
client = Deaddrop.local()
```

### Environment Variables

Override discovery with environment variables:

```bash
# Force local backend
export DEADDROP_PATH=/path/to/.deaddrop

# Force remote backend
export DEADDROP_URL=https://deaddrop.example.com
```

## Full Workflow Example

```python
from deadrop import Deaddrop

# Create or open local deaddrop
client = Deaddrop.create_local()

# Create namespace
ns = client.create_namespace(display_name="Agent Communication")

# Create identities
alice = client.create_identity(ns["ns"], display_name="Alice")
bob = client.create_identity(ns["ns"], display_name="Bob")

# Send message
msg = client.send_message(
    ns=ns["ns"],
    from_secret=alice["secret"],
    to_id=bob["id"],
    body="Hello Bob!"
)

# Read inbox
messages = client.get_inbox(
    ns=ns["ns"],
    identity_id=bob["id"],
    secret=bob["secret"]
)

for m in messages:
    print(f"From: {m['from']}")
    print(f"Body: {m['body']}")
```

## CLI Commands with Local Support

### Create namespace

```bash
# Local
deadrop ns create --local --display-name "My Project"

# Remote (existing behavior)
deadrop ns create --display-name "My Project"
```

### List namespaces

```bash
# Show both local and config namespaces
deadrop ns list

# Local only
deadrop ns list --local

# Remote only
deadrop ns list --remote
```

## Same Semantics as Remote

Local namespaces use the same database schema and logic as the server:

- **Message TTL**: Messages expire after being read (configurable per namespace)
- **Archiving**: Messages can be archived to preserve them
- **Identities**: Same secret-based authentication model
- **Invites**: Not applicable locally (direct file access)

## Use Cases

### Unit Testing

Local namespaces are ideal for testing agent communication:

```python
def test_agent_communication():
    client = Deaddrop.in_memory()  # Even faster - no files
    
    setup = client.quick_setup("Test", ["Agent1", "Agent2"])
    
    client.send_message(
        setup["namespace"]["ns"],
        setup["identities"]["Agent1"]["secret"],
        setup["identities"]["Agent2"]["id"],
        "Task complete"
    )
    
    messages = client.get_inbox(
        setup["namespace"]["ns"],
        setup["identities"]["Agent2"]["id"],
        setup["identities"]["Agent2"]["secret"]
    )
    
    assert len(messages) == 1
```

### Offline Development

Work without network connectivity:

```bash
# Initialize once
deadrop ns create --local --display-name "Dev"
deadrop identity create <ns_id> --display-name "Agent"

# Use CLI for testing
deadrop message send <ns_id> <recipient_id> "Test message"
deadrop message inbox <ns_id>
```

### Project-Specific Configuration

Each project can have its own `.deaddrop` for isolated agent communication:

```
my-project/
├── .deaddrop/
│   ├── config.yaml
│   └── data.db
├── src/
└── tests/
```

## Best Practices

1. **Add to .gitignore**: Automatically done when creating with `Deaddrop.create_local()`
2. **Use in-memory for tests**: `Deaddrop.in_memory()` is faster and needs no cleanup
3. **Close connections**: Use context managers or call `client.close()`

```python
# Context manager (recommended)
with Deaddrop.local() as client:
    ns = client.create_namespace("Test")
    # ... use client ...
# Automatically closed
```
