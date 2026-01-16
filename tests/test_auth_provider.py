"""Tests for pluggable auth provider system."""

import os
from unittest.mock import patch


from deadrop.auth_provider import (
    AuthResult,
    extract_bearer_token,
    get_auth_method_name,
    is_auth_enabled,
    verify_bearer_token,
)


class TestAuthResult:
    def test_auth_result_defaults(self):
        result = AuthResult(valid=True)
        assert result.valid is True
        assert result.key_id is None
        assert result.name is None
        assert result.metadata is None
        assert result.error is None

    def test_auth_result_with_values(self):
        result = AuthResult(
            valid=True,
            key_id="key123",
            name="Test Key",
            metadata={"scope": "admin"},
        )
        assert result.valid is True
        assert result.key_id == "key123"
        assert result.name == "Test Key"
        assert result.metadata == {"scope": "admin"}


class TestIsAuthEnabled:
    def test_disabled_when_no_config(self):
        with patch.dict(os.environ, {}, clear=True):
            # Remove any auth-related env vars
            os.environ.pop("DEADROP_AUTH_MODULE", None)
            os.environ.pop("HEARE_AUTH_URL", None)
            assert is_auth_enabled() is False

    def test_enabled_with_heare_auth_url(self):
        with patch.dict(os.environ, {"HEARE_AUTH_URL": "https://auth.example.com"}):
            assert is_auth_enabled() is True

    def test_enabled_with_custom_module(self):
        # Create a mock module with a static method
        mock_module = type("MockAuth", (), {"is_enabled": staticmethod(lambda: True)})

        with patch.dict(os.environ, {"DEADROP_AUTH_MODULE": "mock_auth"}):
            with patch(
                "deadrop.auth_provider.importlib.import_module",
                return_value=mock_module,
            ):
                assert is_auth_enabled() is True


class TestGetAuthMethodName:
    def test_returns_none_when_no_config(self):
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("DEADROP_AUTH_MODULE", None)
            os.environ.pop("HEARE_AUTH_URL", None)
            assert get_auth_method_name() == "none"

    def test_returns_heare_auth(self):
        with patch.dict(os.environ, {"HEARE_AUTH_URL": "https://auth.example.com"}):
            assert get_auth_method_name() == "heare-auth"

    def test_returns_custom_module_name(self):
        with patch.dict(os.environ, {"DEADROP_AUTH_MODULE": "myapp.auth"}):
            assert get_auth_method_name() == "custom:myapp.auth"


class TestExtractBearerToken:
    def test_valid_bearer_token(self):
        assert extract_bearer_token("Bearer abc123") == "abc123"

    def test_bearer_case_insensitive(self):
        assert extract_bearer_token("bearer abc123") == "abc123"
        assert extract_bearer_token("BEARER abc123") == "abc123"

    def test_returns_none_for_invalid_format(self):
        assert extract_bearer_token(None) is None
        assert extract_bearer_token("") is None
        assert extract_bearer_token("Basic abc123") is None
        assert extract_bearer_token("abc123") is None

    def test_strips_whitespace(self):
        assert extract_bearer_token("Bearer  abc123 ") == "abc123"


class TestVerifyBearerToken:
    def test_returns_error_when_no_module(self):
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("DEADROP_AUTH_MODULE", None)
            os.environ.pop("HEARE_AUTH_URL", None)
            result = verify_bearer_token("test-token")
            assert result.valid is False
            assert result.error is not None
            assert "No auth module configured" in result.error

    def test_delegates_to_heare_auth(self):
        with patch.dict(os.environ, {"HEARE_AUTH_URL": "https://auth.example.com"}):
            with patch("deadrop.heare_auth.verify_bearer_token") as mock_verify:
                mock_verify.return_value = AuthResult(valid=True, key_id="key123")
                result = verify_bearer_token("test-token")
                assert result.valid is True
                assert result.key_id == "key123"
                mock_verify.assert_called_once_with("test-token")
