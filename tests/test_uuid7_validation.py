"""Tests for UUID v7 validation on API endpoints."""
import pytest
from deadrop.api import _is_valid_uuid7, _require_uuid7
from fastapi.exceptions import HTTPException


class TestUUID7Validation:
    """Unit tests for UUID v7 validation helper."""

    def test_valid_uuid7(self):
        # Real UUID v7 from production
        assert _is_valid_uuid7("069f56ee-6ead-7394-8000-20d966e7dc6e")

    def test_rejects_uuid4(self):
        # UUID v4 has '4' at position 14
        assert not _is_valid_uuid7("1e141d46-f442-4391-b714-98aeb44c442f")

    def test_rejects_uuid1(self):
        assert not _is_valid_uuid7("550e8400-e29b-11d4-a716-446655440000")

    def test_rejects_garbage(self):
        assert not _is_valid_uuid7("not-a-uuid")
        assert not _is_valid_uuid7("")

    def test_rejects_ffffffff(self):
        assert not _is_valid_uuid7("ffffffff-ffff-ffff-ffff-ffffffffffff")

    def test_require_uuid7_none_is_ok(self):
        """None values should pass (they mean 'not provided')."""
        _require_uuid7(None, "test")  # should not raise

    def test_require_uuid7_valid(self):
        _require_uuid7("069f56ee-6ead-7394-8000-20d966e7dc6e", "test")

    def test_require_uuid7_invalid_raises(self):
        with pytest.raises(HTTPException) as exc_info:
            _require_uuid7("1e141d46-f442-4391-b714-98aeb44c442f", "cursor")
        assert exc_info.value.status_code == 400
        assert "UUID v7" in str(exc_info.value.detail)


class TestUUID7EndpointValidation:
    """Integration tests: non-v7 UUIDs rejected at API level."""

    @pytest.fixture
    def client(self):
        from fastapi.testclient import TestClient
        from deadrop.api import app
        return TestClient(app)

    @pytest.fixture
    def admin_headers(self):
        return {"X-Admin-Token": "test-admin-token"}

    @pytest.fixture
    def setup(self, client, admin_headers):
        """Create namespace, identity, room."""
        ns_resp = client.post("/admin/namespaces", headers=admin_headers)
        ns_data = ns_resp.json()
        ns = ns_data["ns"]
        ns_secret = ns_data["secret"]

        id_resp = client.post(
            f"/{ns}/identities",
            headers={"X-Namespace-Secret": ns_secret},
            json={"metadata": {"display_name": "tester"}},
        )
        identity = id_resp.json()

        room_resp = client.post(
            f"/{ns}/rooms",
            headers={"X-Inbox-Secret": identity["secret"]},
            json={"display_name": "test-room"},
        )
        room = room_resp.json()
        return {
            "ns": ns,
            "ns_secret": ns_secret,
            "identity_id": identity["id"],
            "identity_secret": identity["secret"],
            "room_id": room["room_id"],
        }

    def test_subscribe_rejects_non_v7_cursor(self, client, setup):
        resp = client.post(
            f"/{setup['ns']}/subscribe",
            headers={"X-Inbox-Secret": setup['identity_secret']},
            json={
                "topics": {f"room:{setup['room_id']}": "1e141d46-f442-4391-b714-98aeb44c442f"},
                "mode": "poll",
                "timeout": 1,
            },
        )
        assert resp.status_code == 400
        assert "UUID v7" in resp.json()["detail"]

    def test_subscribe_accepts_v7_cursor(self, client, setup):
        # Send a message to get a real v7 mid
        send_resp = client.post(
            f"/{setup['ns']}/rooms/{setup['room_id']}/messages",
            headers={"X-Inbox-Secret": setup['identity_secret']},
            json={"body": "hello"},
        )
        mid = send_resp.json()["mid"]

        resp = client.post(
            f"/{setup['ns']}/subscribe",
            headers={"X-Inbox-Secret": setup['identity_secret']},
            json={
                "topics": {f"room:{setup['room_id']}": mid},
                "mode": "poll",
                "timeout": 1,
            },
        )
        assert resp.status_code == 200

    def test_subscribe_accepts_null_cursor(self, client, setup):
        resp = client.post(
            f"/{setup['ns']}/subscribe",
            headers={"X-Inbox-Secret": setup['identity_secret']},
            json={
                "topics": {f"room:{setup['room_id']}": None},
                "mode": "poll",
                "timeout": 1,
            },
        )
        assert resp.status_code == 200

    def test_send_room_message_rejects_non_v7_reference(self, client, setup):
        resp = client.post(
            f"/{setup['ns']}/rooms/{setup['room_id']}/messages",
            headers={"X-Inbox-Secret": setup['identity_secret']},
            json={
                "body": "test",
                "reference_mid": "1e141d46-f442-4391-b714-98aeb44c442f",
            },
        )
        assert resp.status_code == 400
        assert "UUID v7" in resp.json()["detail"]

    def test_read_cursor_rejects_non_v7(self, client, setup):
        resp = client.post(
            f"/{setup['ns']}/rooms/{setup['room_id']}/read",
            headers={"X-Inbox-Secret": setup['identity_secret']},
            json={"last_read_mid": "1e141d46-f442-4391-b714-98aeb44c442f"},
        )
        assert resp.status_code == 400
        assert "UUID v7" in resp.json()["detail"]

    def test_get_messages_rejects_non_v7_after(self, client, setup):
        resp = client.get(
            f"/{setup['ns']}/rooms/{setup['room_id']}/messages",
            headers={"X-Inbox-Secret": setup['identity_secret']},
            params={"after": "1e141d46-f442-4391-b714-98aeb44c442f"},
        )
        assert resp.status_code == 400
        assert "UUID v7" in resp.json()["detail"]

    def test_get_inbox_rejects_non_v7_after(self, client, setup):
        resp = client.get(
            f"/{setup['ns']}/inbox/{setup['identity_id']}",
            headers={"X-Inbox-Secret": setup['identity_secret']},
            params={"after": "1e141d46-f442-4391-b714-98aeb44c442f"},
        )
        assert resp.status_code == 400
        assert "UUID v7" in resp.json()["detail"]
