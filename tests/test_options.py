"""Tests for DeaddropOptions configuration class."""

import pytest

from deadrop.options import DeaddropOptions, DeaddropConfigError


class TestDeaddropOptions:
    """Test DeaddropOptions configuration."""

    def test_default_options_auto_discover(self):
        """Default options should enable auto-discovery."""
        opts = DeaddropOptions()
        assert opts.is_auto_discover()
        assert opts.backend_type is None

    def test_local_with_path(self, tmp_path):
        """Explicit path implies local backend."""
        test_path = tmp_path / ".deaddrop"
        opts = DeaddropOptions(path=str(test_path))
        assert opts.is_local()
        assert opts.resolved_path == test_path
        assert not opts.is_auto_discover()

    def test_local_with_flag(self):
        """local=True enables local auto-discovery."""
        opts = DeaddropOptions(local=True)
        assert opts.is_local()
        assert opts.resolved_path is None  # Will be resolved during discovery
        assert not opts.is_auto_discover()

    def test_remote_with_url(self):
        """URL implies remote backend."""
        opts = DeaddropOptions(url="https://deaddrop.example.com")
        assert opts.is_remote()
        assert opts.resolved_url == "https://deaddrop.example.com"
        assert not opts.is_auto_discover()

    def test_remote_url_trailing_slash_stripped(self):
        """Trailing slash should be stripped from URL."""
        opts = DeaddropOptions(url="https://deaddrop.example.com/")
        assert opts.resolved_url == "https://deaddrop.example.com"

    def test_in_memory(self):
        """in_memory=True enables in-memory backend."""
        opts = DeaddropOptions(in_memory=True)
        assert opts.is_in_memory()
        assert not opts.is_auto_discover()

    def test_mutual_exclusivity_local_and_remote(self):
        """Cannot mix local and remote options."""
        with pytest.raises(DeaddropConfigError, match="Cannot mix"):
            DeaddropOptions(path="/tmp/.deaddrop", url="https://example.com")

    def test_mutual_exclusivity_in_memory_and_path(self):
        """Cannot mix in_memory with path."""
        with pytest.raises(DeaddropConfigError, match="in_memory cannot be combined"):
            DeaddropOptions(in_memory=True, path="/tmp/.deaddrop")

    def test_mutual_exclusivity_in_memory_and_local(self):
        """Cannot mix in_memory with local flag."""
        with pytest.raises(DeaddropConfigError, match="in_memory cannot be combined"):
            DeaddropOptions(in_memory=True, local=True)

    def test_create_if_missing_only_for_local(self):
        """create_if_missing only applies to local backends."""
        with pytest.raises(DeaddropConfigError, match="create_if_missing only applies"):
            DeaddropOptions(url="https://example.com", create_if_missing=True)

    def test_factory_for_local(self, tmp_path):
        """Test for_local factory method."""
        opts = DeaddropOptions.for_local()
        assert opts.is_local()
        assert opts.local is True

        test_path = tmp_path / ".deaddrop"
        opts_with_path = DeaddropOptions.for_local(path=str(test_path))
        assert opts_with_path.is_local()
        assert opts_with_path.resolved_path == test_path

    def test_factory_for_remote(self):
        """Test for_remote factory method."""
        opts = DeaddropOptions.for_remote("https://example.com", bearer_token="token123")
        assert opts.is_remote()
        assert opts.resolved_url == "https://example.com"
        assert opts.bearer_token == "token123"

    def test_factory_for_in_memory(self):
        """Test for_in_memory factory method."""
        opts = DeaddropOptions.for_in_memory()
        assert opts.is_in_memory()

    def test_to_dict(self, tmp_path):
        """Test serialization to dict."""
        test_path = tmp_path / ".deaddrop"
        opts = DeaddropOptions(path=str(test_path), create_if_missing=True)
        d = opts.to_dict()
        assert d["backend_type"] == "local"
        assert d["path"] == str(test_path)
        assert d["create_if_missing"] is True


class TestEnvironmentVariables:
    """Test environment variable handling."""

    def test_deaddrop_path_env(self, monkeypatch):
        """DEADDROP_PATH environment variable overrides to local."""
        monkeypatch.setenv("DEADDROP_PATH", "/env/path/.deaddrop")
        opts = DeaddropOptions()
        assert opts.path == "/env/path/.deaddrop"
        assert opts.is_local()

    def test_deaddrop_url_env(self, monkeypatch):
        """DEADDROP_URL environment variable overrides to remote."""
        monkeypatch.setenv("DEADDROP_URL", "https://env.example.com")
        opts = DeaddropOptions()
        assert opts.is_remote()
        assert opts.resolved_url == "https://env.example.com"

    def test_deaddrop_bearer_token_env(self, monkeypatch):
        """DEADDROP_BEARER_TOKEN environment variable is used."""
        monkeypatch.setenv("DEADDROP_URL", "https://example.com")
        monkeypatch.setenv("DEADDROP_BEARER_TOKEN", "env_token")
        opts = DeaddropOptions()
        assert opts.bearer_token == "env_token"

    def test_explicit_overrides_env(self, monkeypatch):
        """Explicit options should still work with env vars set."""
        monkeypatch.setenv("DEADDROP_URL", "https://env.example.com")
        # in_memory is explicit and should work
        opts = DeaddropOptions(in_memory=True)
        assert opts.is_in_memory()
