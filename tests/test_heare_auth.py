"""Tests for heare-auth integration."""

import os
from unittest.mock import patch, MagicMock


from deadrop.heare_auth import (
    extract_bearer_token,
    is_heare_auth_enabled,
    verify_bearer_token,
)


class TestExtractBearerToken:
    def test_valid_bearer_token(self):
        assert extract_bearer_token("Bearer abc123") == "abc123"
        assert extract_bearer_token("bearer ABC123") == "ABC123"
        assert extract_bearer_token("BEARER token_with_underscores") == "token_with_underscores"

    def test_bearer_with_spaces(self):
        assert extract_bearer_token("Bearer   token_with_spaces  ") == "token_with_spaces"

    def test_invalid_formats(self):
        assert extract_bearer_token(None) is None
        assert extract_bearer_token("") is None
        assert extract_bearer_token("Basic abc123") is None
        assert extract_bearer_token("Bearertoken") is None  # No space
        assert extract_bearer_token("abc123") is None  # No scheme


class TestIsHeareAuthEnabled:
    def test_enabled_when_url_set(self):
        with patch.dict(os.environ, {"HEARE_AUTH_URL": "https://auth.example.com"}):
            assert is_heare_auth_enabled() is True

    def test_disabled_when_url_not_set(self):
        env = os.environ.copy()
        env.pop("HEARE_AUTH_URL", None)
        with patch.dict(os.environ, env, clear=True):
            assert is_heare_auth_enabled() is False

    def test_disabled_when_url_empty(self):
        with patch.dict(os.environ, {"HEARE_AUTH_URL": ""}):
            assert is_heare_auth_enabled() is False


class TestVerifyBearerToken:
    def test_returns_error_when_not_configured(self):
        env = os.environ.copy()
        env.pop("HEARE_AUTH_URL", None)
        with patch.dict(os.environ, env, clear=True):
            result = verify_bearer_token("some_token")
            assert result.valid is False
            assert result.error is not None
            assert "not configured" in result.error

    @patch("deadrop.heare_auth.httpx.post")
    def test_valid_token(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "valid": True,
            "key_id": "key_123",
            "name": "Test Key",
            "metadata": {"role": "admin"},
        }
        mock_post.return_value = mock_response

        with patch.dict(os.environ, {"HEARE_AUTH_URL": "https://auth.example.com"}):
            result = verify_bearer_token("valid_token")

            assert result.valid is True
            assert result.key_id == "key_123"
            assert result.name == "Test Key"
            assert result.metadata == {"role": "admin"}

            mock_post.assert_called_once_with(
                "https://auth.example.com/verify",
                json={"api_key": "valid_token"},
                timeout=5.0,
            )

    @patch("deadrop.heare_auth.httpx.post")
    def test_invalid_token(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "valid": False,
            "error": "Invalid API key",
        }
        mock_post.return_value = mock_response

        with patch.dict(os.environ, {"HEARE_AUTH_URL": "https://auth.example.com"}):
            result = verify_bearer_token("invalid_token")

            assert result.valid is False
            assert result.error == "Invalid API key"

    @patch("deadrop.heare_auth.httpx.post")
    def test_auth_service_error(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_post.return_value = mock_response

        with patch.dict(os.environ, {"HEARE_AUTH_URL": "https://auth.example.com"}):
            result = verify_bearer_token("some_token")

            assert result.valid is False
            assert result.error is not None
            assert "500" in result.error

    @patch("deadrop.heare_auth.httpx.post")
    def test_auth_service_unavailable(self, mock_post):
        import httpx

        mock_post.side_effect = httpx.RequestError("Connection refused")

        with patch.dict(os.environ, {"HEARE_AUTH_URL": "https://auth.example.com"}):
            result = verify_bearer_token("some_token")

            assert result.valid is False
            assert result.error is not None
            assert "unavailable" in result.error
