"""Tests for backend error handling and exception types."""

import pytest

from deadrop.backends import AuthenticationError, DeaddropAPIError


class TestExceptionHierarchy:
    """Verify exception class hierarchy."""

    def test_auth_error_is_api_error(self):
        """AuthenticationError is a subclass of DeaddropAPIError."""
        assert issubclass(AuthenticationError, DeaddropAPIError)

    def test_api_error_is_exception(self):
        """DeaddropAPIError is a subclass of Exception."""
        assert issubclass(DeaddropAPIError, Exception)

    def test_auth_error_has_status_code(self):
        """AuthenticationError carries the status code."""
        err = AuthenticationError("Forbidden", status_code=403)
        assert err.status_code == 403
        assert "Forbidden" in str(err)

    def test_api_error_has_status_code(self):
        """DeaddropAPIError carries the status code."""
        err = DeaddropAPIError("Server Error", status_code=500)
        assert err.status_code == 500

    def test_catching_api_error_catches_auth_error(self):
        """Catching DeaddropAPIError also catches AuthenticationError."""
        with pytest.raises(DeaddropAPIError):
            raise AuthenticationError("Forbidden", status_code=403)


class TestRemoteBackendRequest:
    """Tests for RemoteBackend._request error handling."""

    @pytest.fixture
    def mock_backend(self):
        """Create a RemoteBackend with a mocked HTTP client."""
        from unittest.mock import MagicMock

        from deadrop.backends import RemoteBackend

        backend = RemoteBackend.__new__(RemoteBackend)
        backend._url = "https://example.com"
        backend._bearer_token = None
        backend._client = MagicMock()
        return backend

    def test_request_401_raises_auth_error(self, mock_backend):
        """401 response raises AuthenticationError."""
        mock_backend._client.request.return_value = _mock_response(401, "Unauthorized")

        with pytest.raises(AuthenticationError) as exc_info:
            mock_backend._request("GET", "/test")

        assert exc_info.value.status_code == 401

    def test_request_403_raises_auth_error(self, mock_backend):
        """403 response raises AuthenticationError."""
        mock_backend._client.request.return_value = _mock_response(403, "Forbidden")

        with pytest.raises(AuthenticationError) as exc_info:
            mock_backend._request("GET", "/test")

        assert exc_info.value.status_code == 403

    def test_request_404_raises_api_error(self, mock_backend):
        """404 response raises DeaddropAPIError (not AuthenticationError)."""
        mock_backend._client.request.return_value = _mock_response(404, "Not Found")

        with pytest.raises(DeaddropAPIError) as exc_info:
            mock_backend._request("GET", "/test")

        assert exc_info.value.status_code == 404
        assert not isinstance(exc_info.value, AuthenticationError)

    def test_request_500_raises_api_error(self, mock_backend):
        """500 response raises DeaddropAPIError."""
        mock_backend._client.request.return_value = _mock_response(500, "Internal Error")

        with pytest.raises(DeaddropAPIError) as exc_info:
            mock_backend._request("GET", "/test")

        assert exc_info.value.status_code == 500

    def test_request_200_returns_json(self, mock_backend):
        """200 response returns parsed JSON."""
        resp = _mock_response(200, '{"ok": true}')
        resp.json.return_value = {"ok": True}
        resp.content = b'{"ok": true}'
        mock_backend._client.request.return_value = resp

        result = mock_backend._request("GET", "/test")
        assert result == {"ok": True}


def _mock_response(status_code, text=""):
    """Create a mock HTTP response."""
    from unittest.mock import MagicMock

    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.content = text.encode() if text else b""
    return resp
