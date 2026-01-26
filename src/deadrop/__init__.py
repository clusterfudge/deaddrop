"""deaddrop - Minimal inbox-only messaging for agents.

Usage:
    from deadrop import Deaddrop, DeaddropOptions

    # Auto-discover backend (local .deaddrop or remote config)
    client = Deaddrop()

    # Explicit backends
    client = Deaddrop.local()
    client = Deaddrop.remote(url="https://deaddrop.example.com")
    client = Deaddrop.in_memory()

    # Create new local .deaddrop
    client = Deaddrop.create_local()

    # Full workflow
    ns = client.create_namespace(display_name="My Project")
    alice = client.create_identity(ns["ns"], display_name="Alice")
    bob = client.create_identity(ns["ns"], display_name="Bob")

    client.send_message(ns["ns"], alice["secret"], bob["id"], "Hello!")
    messages = client.get_inbox(ns["ns"], bob["id"], bob["secret"])
"""

from deadrop._version import __version__
from deadrop.client import Deaddrop
from deadrop.discovery import DeaddropNotFound
from deadrop.options import DeaddropConfigError, DeaddropOptions

__all__ = [
    "__version__",
    "Deaddrop",
    "DeaddropOptions",
    "DeaddropNotFound",
    "DeaddropConfigError",
]
