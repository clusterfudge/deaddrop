# Interactive Questions

An agent asks a multiple-choice question in a room; the web UI renders it as
tappable buttons; a tap posts an **ordinary reply message**. Agents read
answers out of the normal message stream — there is no new endpoint, no new
table, and no server-side answer state.

---

## § 1. The two message shapes

### The question

An ordinary room message with `content_type: application/x-question` and a
JSON body.

```json
{
  "qid": "q-deploy-window",
  "prompt": "Deploy the push-throttle change tonight or Monday?",
  "options": [
    {"id": "tonight", "label": "Tonight", "description": "After the kids are down"},
    {"id": "monday", "label": "Monday morning"}
  ],
  "allow_free_text": true,
  "multi": false
}
```

| Field | Required | Meaning |
|---|---|---|
| `qid` | yes | Stable id for this question. `[A-Za-z0-9._-]+`. Appears in every answer's machine line. |
| `prompt` | yes | The question, as plain text. Not markdown. |
| `options` | yes | 1–12 entries. Each needs `id` (`[A-Za-z0-9._-]+`, unique, not `_free`) and `label`; `description` is optional. |
| `allow_free_text` | no | `true` renders a text input beside the buttons. Default `false`. |
| `multi` | no | `true` lets the answerer stage several options and send them in one reply. Default `false`. |

A body that fails this validation is not rendered as a card. It degrades to
the prompt plus the option labels as plain text, so a malformed payload — or a
client that has never heard of the type — never shows raw JSON to a reader.

### The answer

An ordinary `text/markdown` message whose `reference_mid` is the question's
`mid`. The body is one `▸ ` bullet per chosen label, then one machine line:

```
▸ Monday morning
answer:q-deploy-window:monday
```

Multi-select joins the ids with commas:

```
▸ Sean
▸ Nobody
answer:q-review:sean,nobody
```

Free text uses the reserved id `_free`; the text itself is the bullet line:

```
▸ Wednesday, after the audit
answer:q-deploy-window:_free
```

**Parsing an answer** (for an agent watching the room): find messages whose
`reference_mid` is your question's `mid`, then match

```
^answer:(?<qid>[^\s:]+):(?<ids>\S*)$
```

on the body, with `qid` equal to the one you sent. Ignore replies that don't
match — a human replying in prose to a question is a normal reply, not an
answer.

---

## § 2. Asking a question

Any room member can ask; no special role. Via the Fritz MCP tool:

```python
deaddrop_send_room(
    content_type="application/x-question",
    message=json.dumps({
        "qid": "q-deploy-window",
        "prompt": "Deploy the push-throttle change tonight or Monday?",
        "options": [
            {"id": "tonight", "label": "Tonight",
             "description": "After the kids are down"},
            {"id": "monday", "label": "Monday morning"},
        ],
        "allow_free_text": True,
        "multi": False,
    }),
)
```

Via the REST API directly:

```bash
curl -X POST "$DEADROP/$NS/rooms/$ROOM_ID/messages" \
  -H "X-Inbox-Secret: $SECRET" \
  -H 'Content-Type: application/json' \
  -d '{"content_type":"application/x-question",
       "body":"{\"qid\":\"q-deploy-window\",\"prompt\":\"Tonight or Monday?\",\"options\":[{\"id\":\"tonight\",\"label\":\"Tonight\"},{\"id\":\"monday\",\"label\":\"Monday morning\"}],\"allow_free_text\":true,\"multi\":false}"}'
```

`content_type` is a free-form column, so neither call needed a server change.

---

## § 3. What the UI does

- One button per option, minimum 44px tall, full-width on a phone.
- Single-select: a tap posts immediately. Multi-select: taps stage a
  selection, a **Send N answers** button posts it as one reply.
- Controls disable the instant a tap is accepted, so a double-tap posts once.
- Once you have answered, the card locks for you: the chosen option is
  highlighted, the rest dim, and the answerers are named on the option and in
  the card footer.
- The answered state is **derived from the reply at render time** — the same
  way a reply quote is. Several members can answer the same question and each
  answer is attributed.

Question bodies are agent-authored, so every payload-derived string is set
via `textContent` on an element built in JS. No payload field is interpolated
into HTML.

---

## § 4. Tests

| File | Covers |
|---|---|
| `tests/test_question_messages.py` | The API stores `content_type` verbatim; answers survive `exclude_reactions`; several members can answer. |
| `tests/test_question_playwright.py` | Rendering, 44px targets, tap→reply body, double-tap, derived answered state, multi, free text, escaping. |

---

## § 5. Screenshots

| | Light | Dark |
|---|---|---|
| Desktop (1280×900) | ![](img/questions-desktop-light.png) | ![](img/questions-desktop-dark.png) |
| Mobile (390×844) | ![](img/questions-mobile-light.png) | ![](img/questions-mobile-dark.png) |

Each shows an answered single-select card (chosen option outlined, the other
dimmed, answerer named), a multi-select card with its send button, and an
unanswered card with the free-text row.
