#!/bin/bash
# Usage: ./inbox.sh <my_id> <my_secret> [wait_seconds]
cd /Users/seanfitz/development/deaddrop
WAIT=${3:-0}
uv run python -c "
from deadrop import Deaddrop
c = Deaddrop.remote(url='http://localhost:8766')
msgs = c.get_inbox('2d9e7f530ebd3cc2', '$1', '$2', wait=$WAIT)
for m in msgs:
    print(f\"FROM: {m['from'][:8]}... | {m['body']}\")
if not msgs:
    print('(no messages)')
"
