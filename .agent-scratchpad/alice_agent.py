#!/usr/bin/env python3
"""Alice - argues FOR mandatory AI explainability. Uses long-polling."""

from deadrop import Deaddrop

NS = "55894f103c6bf9a8"
MY_ID = "026d55f4ad1803d2"
MY_SECRET = "97adeb431f6b9ee549143434b99a73903859338ea3ba30d209607b9fdf05e110"
MOD_ID = "a8b39b2d35778a66"
BOB_ID = "b4e5d6936556666e"

client = Deaddrop.remote(url="http://localhost:8766")
seen = set()


def send(to_id, name, msg):
    client.send_message(NS, MY_SECRET, to_id, msg)
    print(f"[SENT to {name}]: {msg}\n", flush=True)


def check(wait=10):
    """Check inbox with long-polling."""
    msgs = client.get_inbox(NS, MY_ID, MY_SECRET, wait=wait)  # Long-polling enabled
    new = []
    for m in msgs:
        if m["mid"] not in seen:
            seen.add(m["mid"])
            who = "MOD" if m["from"] == MOD_ID else "BOB" if m["from"] == BOB_ID else "?"
            print(f"[FROM {who}]: {m['body']}\n", flush=True)
            new.append((who, m["body"]))
    return new


print("=== ALICE online (FOR explainability) - Using Long-Polling ===\n", flush=True)

# Wait for moderator
while True:
    new = check(15)
    if any(w == "MOD" for w, _ in new):
        break

# Opening argument
opening = "AI systems make life-changing decisions in healthcare, justice, and finance. Without explainability, we have unaccountable black boxes. People deserve to know WHY."
send(BOB_ID, "BOB", opening)
send(MOD_ID, "MOD", f"[Opening] {opening}")

# Debate loop
turns = 0
while turns < 3:
    new = check(15)  # Long-poll for 15 seconds
    for who, body in new:
        if who == "BOB":
            turns += 1
            if turns == 1:
                reply = "False choice! SHAP values and attention maps work. Corporate reluctance, not tech limits, is the barrier."
            elif turns == 2:
                reply = "Compromise: skip explanations for low-stakes AI. But medical/legal/financial AI MUST be explainable."
            else:
                reply = "Agreed - targeted rules for high-stakes AI. Good debate!"
            send(BOB_ID, "BOB", reply)
            send(MOD_ID, "MOD", f"[Reply {turns}] {reply}")
        elif who == "MOD" and "clos" in body.lower():
            send(MOD_ID, "MOD", "Thanks! Explainability = accountability.")
            print("=== ALICE signing off ===", flush=True)
            exit(0)

print("=== ALICE waiting for closing ===", flush=True)
for _ in range(6):
    new = check(10)
    if any("clos" in b.lower() for _, b in new):
        send(MOD_ID, "MOD", "Thanks!")
        break
print("=== ALICE exiting ===", flush=True)
