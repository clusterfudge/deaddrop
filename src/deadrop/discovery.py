"""Discovery logic for finding deaddrop configurations.

Provides utilities for:
- Finding git repository roots
- Locating .deaddrop directories
- Auto-discovering backend configuration
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .config import GlobalConfig, get_global_config_path


class DeaddropNotFound(Exception):
    """Raised when no deaddrop configuration can be found."""

    pass


def find_git_root(start_path: Path | str | None = None) -> Path | None:
    """Find the root of the git repository containing start_path.

    Walks up the directory tree looking for a .git directory.

    Args:
        start_path: Starting directory. Defaults to current working directory.

    Returns:
        Path to git root, or None if not in a git repository.

    Example:
        >>> find_git_root("/path/to/repo/src/module")
        Path("/path/to/repo")
    """
    if start_path is None:
        start_path = Path.cwd()
    else:
        start_path = Path(start_path)

    path = start_path.resolve()

    while path != path.parent:
        if (path / ".git").exists():
            return path
        path = path.parent

    # Check root directory too
    if (path / ".git").exists():
        return path

    return None


def find_deaddrop_dir(start_path: Path | str | None = None) -> Path | None:
    """Find a .deaddrop directory, checking CWD first, then git root.

    Args:
        start_path: Starting directory. Defaults to current working directory.

    Returns:
        Path to .deaddrop directory, or None if not found.

    Search order:
        1. {start_path}/.deaddrop
        2. {git_root}/.deaddrop (if in a git repo)
    """
    if start_path is None:
        start_path = Path.cwd()
    else:
        start_path = Path(start_path).resolve()

    # Check CWD first
    cwd_deaddrop = start_path / ".deaddrop"
    if cwd_deaddrop.is_dir():
        return cwd_deaddrop

    # Check git root
    git_root = find_git_root(start_path)
    if git_root:
        git_deaddrop = git_root / ".deaddrop"
        if git_deaddrop.is_dir():
            return git_deaddrop

    return None


def get_deaddrop_init_path(start_path: Path | str | None = None) -> Path:
    """Get the path where a new .deaddrop should be initialized.

    Prefers git root if in a repository, otherwise uses start_path.

    Args:
        start_path: Starting directory. Defaults to current working directory.

    Returns:
        Path where .deaddrop directory should be created.
    """
    if start_path is None:
        start_path = Path.cwd()
    else:
        start_path = Path(start_path).resolve()

    git_root = find_git_root(start_path)
    if git_root:
        return git_root / ".deaddrop"

    return start_path / ".deaddrop"


@dataclass
class DiscoveryResult:
    """Result of backend discovery."""

    backend_type: Literal["local", "remote", "in_memory"]
    """The discovered backend type."""

    path: Path | None = None
    """Path to .deaddrop directory (for local backend)."""

    url: str | None = None
    """Server URL (for remote backend)."""

    bearer_token: str | None = None
    """Bearer token for admin operations (remote backend)."""

    source: str = ""
    """How the backend was discovered (for debugging)."""


def discover_backend(
    start_path: Path | str | None = None,
    require_local: bool = False,
) -> DiscoveryResult:
    """Discover the appropriate backend configuration.

    Discovery order:
        1. Environment variables (DEADDROP_PATH, DEADDROP_URL)
        2. Local .deaddrop directory (CWD, then git root)
        3. Remote configuration (~/.config/deadrop/config.yaml)

    Args:
        start_path: Starting directory for local discovery.
        require_local: If True, only check for local backends.

    Returns:
        DiscoveryResult with backend configuration.

    Raises:
        DeaddropNotFound: If no valid configuration is found.
    """
    # Check environment variables first
    env_path = os.environ.get("DEADDROP_PATH")
    if env_path:
        path = Path(env_path)
        if path.is_dir():
            return DiscoveryResult(
                backend_type="local",
                path=path,
                source="DEADDROP_PATH environment variable",
            )
        raise DeaddropNotFound(f"DEADDROP_PATH points to non-existent directory: {env_path}")

    env_url = os.environ.get("DEADDROP_URL")
    if env_url and not require_local:
        return DiscoveryResult(
            backend_type="remote",
            url=env_url,
            bearer_token=os.environ.get("DEADDROP_BEARER_TOKEN"),
            source="DEADDROP_URL environment variable",
        )

    # Check for local .deaddrop
    local_path = find_deaddrop_dir(start_path)
    if local_path:
        return DiscoveryResult(
            backend_type="local",
            path=local_path,
            source=f"found {local_path}",
        )

    if require_local:
        raise DeaddropNotFound(
            "No local .deaddrop directory found. "
            "Create one with: Deaddrop.create_local() or deadrop ns create --local"
        )

    # Check for remote configuration
    config_path = get_global_config_path()
    if config_path.exists():
        config = GlobalConfig.load()
        if config.url:
            return DiscoveryResult(
                backend_type="remote",
                url=config.url,
                bearer_token=config.bearer_token,
                source=f"loaded from {config_path}",
            )

    raise DeaddropNotFound(
        "No deaddrop configuration found. Options:\n"
        "  - Create a local .deaddrop: Deaddrop.create_local()\n"
        "  - Set DEADDROP_URL environment variable\n"
        "  - Run 'deadrop init' to configure remote server"
    )


def is_in_git_repo(path: Path | str | None = None) -> bool:
    """Check if the given path is inside a git repository."""
    return find_git_root(path) is not None


def ensure_gitignore(deaddrop_path: Path) -> bool:
    """Ensure .deaddrop is in .gitignore if in a git repo.

    Args:
        deaddrop_path: Path to .deaddrop directory.

    Returns:
        True if .gitignore was updated, False otherwise.
    """
    git_root = find_git_root(deaddrop_path.parent)
    if not git_root:
        return False

    gitignore_path = git_root / ".gitignore"
    deaddrop_entry = ".deaddrop/"

    # Check if already ignored
    if gitignore_path.exists():
        content = gitignore_path.read_text()
        lines = content.splitlines()
        for line in lines:
            # Check for exact match or pattern that would match
            stripped = line.strip()
            if stripped in (".deaddrop", ".deaddrop/", "/.deaddrop", "/.deaddrop/"):
                return False

    # Append to .gitignore
    with open(gitignore_path, "a") as f:
        # Add newline if file doesn't end with one
        if gitignore_path.exists():
            content = gitignore_path.read_text()
            if content and not content.endswith("\n"):
                f.write("\n")
        f.write(f"{deaddrop_entry}\n")

    return True
