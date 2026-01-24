"""Tests for discovery logic."""

import pytest

from deadrop.discovery import (
    find_git_root,
    find_deaddrop_dir,
    get_deaddrop_init_path,
    discover_backend,
    ensure_gitignore,
    is_in_git_repo,
    DeaddropNotFound,
)


class TestFindGitRoot:
    """Test git root finding."""

    def test_finds_git_root(self, tmp_path):
        """Should find .git directory."""
        git_dir = tmp_path / ".git"
        git_dir.mkdir()

        # From root
        assert find_git_root(tmp_path) == tmp_path

        # From subdirectory
        subdir = tmp_path / "src" / "module"
        subdir.mkdir(parents=True)
        assert find_git_root(subdir) == tmp_path

    def test_returns_none_if_not_in_git(self, tmp_path):
        """Should return None if not in a git repo."""
        assert find_git_root(tmp_path) is None

    def test_defaults_to_cwd(self, tmp_path, monkeypatch):
        """Should default to current working directory."""
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        monkeypatch.chdir(tmp_path)
        assert find_git_root() == tmp_path


class TestFindDeaddropDir:
    """Test .deaddrop directory finding."""

    def test_finds_in_cwd(self, tmp_path):
        """Should find .deaddrop in current directory."""
        deaddrop_dir = tmp_path / ".deaddrop"
        deaddrop_dir.mkdir()

        assert find_deaddrop_dir(tmp_path) == deaddrop_dir

    def test_finds_in_git_root(self, tmp_path):
        """Should find .deaddrop in git root."""
        # Create git repo structure
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        deaddrop_dir = tmp_path / ".deaddrop"
        deaddrop_dir.mkdir()

        # Search from subdirectory
        subdir = tmp_path / "src" / "module"
        subdir.mkdir(parents=True)

        assert find_deaddrop_dir(subdir) == deaddrop_dir

    def test_cwd_takes_priority_over_git_root(self, tmp_path):
        """CWD .deaddrop should be found first."""
        # Create git repo with .deaddrop at root
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        root_deaddrop = tmp_path / ".deaddrop"
        root_deaddrop.mkdir()

        # Create .deaddrop in subdirectory too
        subdir = tmp_path / "project"
        subdir.mkdir()
        sub_deaddrop = subdir / ".deaddrop"
        sub_deaddrop.mkdir()

        # From subdir, should find subdir's .deaddrop first
        assert find_deaddrop_dir(subdir) == sub_deaddrop

    def test_returns_none_if_not_found(self, tmp_path):
        """Should return None if no .deaddrop found."""
        assert find_deaddrop_dir(tmp_path) is None


class TestGetDeaddropInitPath:
    """Test determining where to create .deaddrop."""

    def test_prefers_git_root(self, tmp_path):
        """Should prefer git root for new .deaddrop."""
        git_dir = tmp_path / ".git"
        git_dir.mkdir()

        subdir = tmp_path / "src"
        subdir.mkdir()

        assert get_deaddrop_init_path(subdir) == tmp_path / ".deaddrop"

    def test_uses_cwd_if_not_git(self, tmp_path):
        """Should use current path if not in git repo."""
        subdir = tmp_path / "project"
        subdir.mkdir()

        assert get_deaddrop_init_path(subdir) == subdir / ".deaddrop"


class TestDiscoverBackend:
    """Test backend discovery logic."""

    def test_discovers_local_from_cwd(self, tmp_path):
        """Should discover local .deaddrop in CWD."""
        deaddrop_dir = tmp_path / ".deaddrop"
        deaddrop_dir.mkdir()

        result = discover_backend(tmp_path)
        assert result.backend_type == "local"
        assert result.path == deaddrop_dir

    def test_env_path_takes_priority(self, tmp_path, monkeypatch):
        """DEADDROP_PATH should take priority."""
        env_path = tmp_path / "env_deaddrop"
        env_path.mkdir()
        monkeypatch.setenv("DEADDROP_PATH", str(env_path))

        # Create local .deaddrop too
        local = tmp_path / "other" / ".deaddrop"
        local.mkdir(parents=True)

        result = discover_backend(tmp_path / "other")
        assert result.backend_type == "local"
        assert result.path == env_path
        assert "environment variable" in result.source

    def test_env_path_missing_raises(self, monkeypatch):
        """DEADDROP_PATH pointing to missing dir should raise."""
        monkeypatch.setenv("DEADDROP_PATH", "/nonexistent/path")

        with pytest.raises(DeaddropNotFound, match="non-existent"):
            discover_backend()

    def test_env_url_takes_priority(self, tmp_path, monkeypatch):
        """DEADDROP_URL should override local discovery."""
        monkeypatch.setenv("DEADDROP_URL", "https://example.com")

        # Create local .deaddrop too
        deaddrop_dir = tmp_path / ".deaddrop"
        deaddrop_dir.mkdir()

        result = discover_backend(tmp_path)
        assert result.backend_type == "remote"
        assert result.url == "https://example.com"

    def test_require_local_ignores_env_url(self, tmp_path, monkeypatch):
        """require_local=True should ignore DEADDROP_URL."""
        monkeypatch.setenv("DEADDROP_URL", "https://example.com")

        deaddrop_dir = tmp_path / ".deaddrop"
        deaddrop_dir.mkdir()

        result = discover_backend(tmp_path, require_local=True)
        assert result.backend_type == "local"
        assert result.path == deaddrop_dir

    def test_require_local_raises_if_not_found(self, tmp_path):
        """require_local=True should raise if no local .deaddrop."""
        with pytest.raises(DeaddropNotFound, match="No local .deaddrop"):
            discover_backend(tmp_path, require_local=True)

    def test_raises_if_nothing_found(self, tmp_path, monkeypatch):
        """Should raise if no configuration found."""
        # Ensure no env vars and no config file
        monkeypatch.delenv("DEADDROP_PATH", raising=False)
        monkeypatch.delenv("DEADDROP_URL", raising=False)
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))

        with pytest.raises(DeaddropNotFound):
            discover_backend(tmp_path)


class TestEnsureGitignore:
    """Test .gitignore management."""

    def test_adds_to_gitignore(self, tmp_path):
        """Should add .deaddrop/ to .gitignore."""
        git_dir = tmp_path / ".git"
        git_dir.mkdir()

        deaddrop_dir = tmp_path / ".deaddrop"
        deaddrop_dir.mkdir()

        result = ensure_gitignore(deaddrop_dir)

        assert result is True
        gitignore = tmp_path / ".gitignore"
        assert gitignore.exists()
        assert ".deaddrop/" in gitignore.read_text()

    def test_does_not_duplicate(self, tmp_path):
        """Should not add if already present."""
        git_dir = tmp_path / ".git"
        git_dir.mkdir()

        gitignore = tmp_path / ".gitignore"
        gitignore.write_text(".deaddrop/\n")

        deaddrop_dir = tmp_path / ".deaddrop"
        deaddrop_dir.mkdir()

        result = ensure_gitignore(deaddrop_dir)

        assert result is False
        # Should still have only one entry
        assert gitignore.read_text().count(".deaddrop") == 1

    def test_handles_various_formats(self, tmp_path):
        """Should recognize various .gitignore patterns."""
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        deaddrop_dir = tmp_path / ".deaddrop"
        deaddrop_dir.mkdir()

        for pattern in [".deaddrop", ".deaddrop/", "/.deaddrop", "/.deaddrop/"]:
            gitignore = tmp_path / ".gitignore"
            gitignore.write_text(f"{pattern}\n")

            result = ensure_gitignore(deaddrop_dir)
            assert result is False, f"Should recognize pattern: {pattern}"

    def test_returns_false_if_not_git(self, tmp_path):
        """Should return False if not in git repo."""
        deaddrop_dir = tmp_path / ".deaddrop"
        deaddrop_dir.mkdir()

        result = ensure_gitignore(deaddrop_dir)
        assert result is False


class TestIsInGitRepo:
    """Test git repo detection helper."""

    def test_true_in_git_repo(self, tmp_path):
        """Should return True inside git repo."""
        git_dir = tmp_path / ".git"
        git_dir.mkdir()

        assert is_in_git_repo(tmp_path) is True

        subdir = tmp_path / "src"
        subdir.mkdir()
        assert is_in_git_repo(subdir) is True

    def test_false_outside_git_repo(self, tmp_path):
        """Should return False outside git repo."""
        assert is_in_git_repo(tmp_path) is False
