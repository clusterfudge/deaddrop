#!/bin/bash
# Usage: ./send.sh <from_secret> <to_id> <message>
cd /Users/seanfitz/development/deaddrop
uv run python -c "
from deadrop import Deaddrop
c = Deaddrop.remote(url='http://localhost:8766')
c.send_message('2d9e7f530ebd3cc2', '$1', '$2', '''$3''')
print('Sent.')
"
