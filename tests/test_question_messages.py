"""Interactive question/answer messages ride the existing room message API.

A question is an ordinary room message with ``content_type`` set to
``application/x-question`` and a JSON body; an answer is an ordinary
``text/markdown`` message whose ``reference_mid`` is the question's mid. These
tests pin the two properties the feature depends on server-side:

  1. ``content_type`` is stored and returned verbatim — no allowlist.
  2. ``exclude_reactions`` does not filter questions or answers out of a page.

If either property changes, the client-side feature breaks silently.
"""

import json

import pytest
from fastapi.testclient import TestClient

from deadrop.api import app

QUESTION_CONTENT_TYPE = "application/x-question"


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def admin_headers():
    return {"X-Admin-Token": "test-admin-token"}


@pytest.fixture
def room(client, admin_headers):
    """A room with Alice (asker) and Bob (answerer) as members."""
    ns = client.post("/admin/namespaces", headers=admin_headers).json()
    ns_headers = {"X-Namespace-Secret": ns["secret"]}

    alice = client.post(
        f"/{ns['ns']}/identities", headers=ns_headers, json={"metadata": {"display_name": "Alice"}}
    ).json()
    bob = client.post(
        f"/{ns['ns']}/identities", headers=ns_headers, json={"metadata": {"display_name": "Bob"}}
    ).json()

    created = client.post(
        f"/{ns['ns']}/rooms",
        headers={"X-Inbox-Secret": alice["secret"]},
        json={"display_name": "Q&A"},
    ).json()
    client.post(
        f"/{ns['ns']}/rooms/{created['room_id']}/members",
        headers={"X-Inbox-Secret": alice["secret"]},
        json={"identity_id": bob["id"]},
    )
    return {"ns": ns["ns"], "room_id": created["room_id"], "alice": alice, "bob": bob}


QUESTION_PAYLOAD = {
    "qid": "q-deploy-window",
    "prompt": "Deploy the push-throttle change tonight or Monday?",
    "options": [
        {"id": "tonight", "label": "Tonight", "description": "After the kids are down"},
        {"id": "monday", "label": "Monday morning"},
    ],
    "allow_free_text": True,
    "multi": False,
}


def _send(client, room, sender, body, content_type, reference_mid=None):
    payload = {"body": body, "content_type": content_type}
    if reference_mid:
        payload["reference_mid"] = reference_mid
    response = client.post(
        f"/{room['ns']}/rooms/{room['room_id']}/messages",
        headers={"X-Inbox-Secret": room[sender]["secret"]},
        json=payload,
    )
    assert response.status_code == 200, response.text
    return response.json()


class TestQuestionRoundTrip:
    def test_question_content_type_is_stored_verbatim(self, client, room):
        """An agent can post a question with no server-side change."""
        sent = _send(client, room, "alice", json.dumps(QUESTION_PAYLOAD), QUESTION_CONTENT_TYPE)
        assert sent["content_type"] == QUESTION_CONTENT_TYPE
        assert json.loads(sent["body"])["qid"] == "q-deploy-window"

        fetched = client.get(
            f"/{room['ns']}/rooms/{room['room_id']}/messages",
            headers={"X-Inbox-Secret": room["alice"]["secret"]},
        ).json()["messages"]
        assert [m["content_type"] for m in fetched] == [QUESTION_CONTENT_TYPE]
        assert json.loads(fetched[0]["body"]) == QUESTION_PAYLOAD

    def test_answer_is_an_ordinary_reply(self, client, room):
        """The answer carries reference_mid and a plain markdown body."""
        question = _send(client, room, "alice", json.dumps(QUESTION_PAYLOAD), QUESTION_CONTENT_TYPE)
        answer = _send(
            client,
            room,
            "bob",
            "\u25b8 Monday morning\nanswer:q-deploy-window:monday",
            "text/markdown",
            reference_mid=question["mid"],
        )

        assert answer["reference_mid"] == question["mid"]
        assert answer["content_type"] == "text/markdown"
        assert "answer:q-deploy-window:monday" in answer["body"]

    def test_questions_and_answers_survive_exclude_reactions(self, client, room):
        """The client's initial page fetch must not filter the pair out."""
        question = _send(client, room, "alice", json.dumps(QUESTION_PAYLOAD), QUESTION_CONTENT_TYPE)
        _send(
            client,
            room,
            "bob",
            "\u25b8 Tonight\nanswer:q-deploy-window:tonight",
            "text/markdown",
            reference_mid=question["mid"],
        )
        _send(client, room, "bob", "\U0001f44d", "reaction", reference_mid=question["mid"])

        page = client.get(
            f"/{room['ns']}/rooms/{room['room_id']}/messages?exclude_reactions=true",
            headers={"X-Inbox-Secret": room["alice"]["secret"]},
        ).json()["messages"]

        types = [m["content_type"] for m in page]
        assert types == [QUESTION_CONTENT_TYPE, "text/markdown"]

    def test_multiple_members_can_answer_the_same_question(self, client, room):
        """Answers are per-sender messages; nothing serializes them."""
        question = _send(client, room, "alice", json.dumps(QUESTION_PAYLOAD), QUESTION_CONTENT_TYPE)
        _send(
            client,
            room,
            "bob",
            "\u25b8 Tonight\nanswer:q-deploy-window:tonight",
            "text/markdown",
            reference_mid=question["mid"],
        )
        _send(
            client,
            room,
            "alice",
            "\u25b8 Monday morning\nanswer:q-deploy-window:monday",
            "text/markdown",
            reference_mid=question["mid"],
        )

        page = client.get(
            f"/{room['ns']}/rooms/{room['room_id']}/messages",
            headers={"X-Inbox-Secret": room["alice"]["secret"]},
        ).json()["messages"]
        answers = [m for m in page if m.get("reference_mid") == question["mid"]]
        assert {m["from_id"] for m in answers} == {room["bob"]["id"], room["alice"]["id"]}
