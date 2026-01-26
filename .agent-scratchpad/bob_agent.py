#!/usr/bin/env python3
"""Bob - argues AGAINST mandatory AI explainability. Uses long-polling."""

import time
from deadrop import Deaddrop

NS = "55894f103c6bf9a8"
MY_ID = "b4e5d6936556666e"
MY_SECRET = "6d4c72a472bc84798eac999d015e42c439679684182cb8edb9cab4d4232e90a5"
MOD_ID = "a8b39b2d35778a66"
ALICE_ID = "026d55f4ad1803d2"

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
            who = "MOD" if m["from"] == MOD_ID else "ALICE" if m["from"] == ALICE_ID else "?"
            print(f"[FROM {who}]: {m['body']}\n", flush=True)
            new.append((who, m["body"]))
    return new


print("=== BOB online (AGAINST mandatory explainability) - Using Long-Polling ===\n", flush=True)

# Wait for Alice's opening
time.sleep(2)
while True:
    new = check(15)  # Long-poll for 15 seconds
    if any(w == "ALICE" for w, _ in new):
        break

# Counter-argument
counter = "Mandatory explainability kills innovation. Deep learning is inherently complex. Forced explanations = worse AI."
send(ALICE_ID, "ALICE", counter)
send(MOD_ID, "MOD", f"[Counter] {counter}")

# Debate loop
turns = 0
while turns < 3:
    new = check(15)  # Long-poll for 15 seconds
    for who, body in new:
        if who == "ALICE":
            turns += 1
            if turns == 1:
                reply = "SHAP/attention are post-hoc rationalizations, not true explanations. They add cost and slow deployment."
            elif turns == 2:
                reply = "Who defines 'high-stakes'? Bureaucrats? Markets and liability law work better than mandates."
            else:
                reply = "Fair - targeted rules, not blanket mandates. Good debate!"
            send(ALICE_ID, "ALICE", reply)
            send(MOD_ID, "MOD", f"[Reply {turns}] {reply}")
        elif who == "MOD" and "clos" in body.lower():
            send(MOD_ID, "MOD", "Thanks! Innovation needs room.")
            print("=== BOB signing off ===", flush=True)
            exit(0)

print("=== BOB waiting for closing ===", flush=True)
for _ in range(6):
    new = check(10)
    if any("clos" in b.lower() for _, b in new):
        send(MOD_ID, "MOD", "Thanks!")
        break
print("=== BOB exiting ===", flush=True)
