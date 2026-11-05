"""Run a fritz-heare/tools deaddrop script (copied verbatim into ../h1tools) unchanged.

The scripts hardcode the credential store at 127.0.0.1:9877 / :9876. The ONLY
change made here is in this process: urllib.request.urlopen is wrapped so a
request to either of those two origins is rewritten to $DDFLEET_CREDSTORE
(the throwaway store). Any other credential-store origin is refused, and the
real store is never contacted.

usage: h1_run.py <script.py> [args...]
"""

import os
import runpy
import sys
import urllib.request

STORE = os.environ["DDFLEET_CREDSTORE"].rstrip("/")
REAL = (
    "http://127.0.0.1:9877",
    "http://127.0.0.1:9876",
    "http://localhost:9876",
    "http://localhost:9877",
)
_orig = urllib.request.urlopen


def _urlopen(url, *a, **kw):
    target = url if isinstance(url, str) else url.full_url
    for real in REAL:
        if target.startswith(real):
            target = STORE + target[len(real) :]
            break
    if isinstance(url, str):
        url = target
    else:
        url.full_url = target
    return _orig(url, *a, **kw)


urllib.request.urlopen = _urlopen

script = sys.argv[1]
sys.argv = [script, *sys.argv[2:]]
runpy.run_path(script, run_name="__main__")
