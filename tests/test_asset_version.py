"""Shell asset URLs carry a content-hash version query.

/static/ is served with ETag and Last-Modified but no Cache-Control, so a
browser may apply heuristic freshness and reuse an asset without revalidating.
The HTML shell is a server-rendered template and is always fresh. Without a
version on the asset URL those two halves of a release land independently:
inline template JS updates while its stylesheet does not, which renders a
feature's markup with the previous release's styles.

These tests pin the three properties that prevent it:

  1. Every same-origin shell asset URL in the rendered HTML carries ?v=.
  2. The token is a function of the assets' bytes, so it changes when they do
     and does not change when they don't.
  3. The versioned URL still serves the asset.
"""

import re

import pytest
from fastapi.testclient import TestClient

from deadrop import api
from deadrop.api import app

# Same-origin asset refs only; CDN <script src="https://..."> is out of scope.
ASSET_REF_RE = re.compile(r'(?:href|src)="(/static/(?:css|js)/[^"]+)"')


@pytest.fixture
def client():
    return TestClient(app)


def _shell_html(client) -> str:
    response = client.get("/app")
    assert response.status_code == 200
    return response.text


def test_every_shell_asset_ref_is_versioned(client):
    refs = ASSET_REF_RE.findall(_shell_html(client))
    assert refs, "no same-origin css/js refs found in the shell"
    unversioned = [r for r in refs if "?v=" not in r]
    assert not unversioned, f"shell asset refs missing a version query: {unversioned}"


def test_stylesheet_ref_carries_the_asset_version(client):
    html = _shell_html(client)
    assert f"/static/css/style.css?v={api._asset_version()}" in html


def test_version_is_stable_across_calls():
    assert api._asset_version() == api._asset_version()


def test_version_tracks_asset_bytes(tmp_path, monkeypatch):
    """The token changes iff a shell asset's bytes change."""
    static = tmp_path / "static"
    (static / "css").mkdir(parents=True)
    (static / "js").mkdir()
    (static / "css" / "style.css").write_text(".a { color: red }")
    for rel in api.SHELL_ASSETS:
        path = static / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch(exist_ok=True)

    monkeypatch.setattr(api, "STATIC_DIR", static)
    before = api._asset_version()
    assert before == api._asset_version()

    (static / "css" / "style.css").write_text(".a { color: blue }")
    assert api._asset_version() != before


def test_missing_asset_does_not_raise(tmp_path, monkeypatch):
    """A shell asset listed but absent hashes as empty rather than exploding."""
    monkeypatch.setattr(api, "STATIC_DIR", tmp_path / "nope")
    assert len(api._asset_version()) == 12


def test_versioned_url_still_serves_the_asset(client):
    response = client.get(f"/static/css/style.css?v={api._asset_version()}")
    assert response.status_code == 200
    assert "question-option" in response.text
