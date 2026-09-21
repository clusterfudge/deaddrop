"""The shell's PWA refresh path: build identity and cache-eviction headers.

An installed web app holds two independent copies of the shell: the browser's
HTTP cache and the service worker's cache. A copy minted under a max-age
freshness lifetime is not evicted by a later header change, and a service
worker that precaches through the HTTP cache copies whatever that cache is
already holding.

These tests pin the properties that keep both copies reachable by a release:

  1. The shell carries a build identifier, and it is rendered into the page.
  2. The two PWA control documents (/sw.js, /manifest.webmanifest) are always
     revalidated.
  3. The service worker precaches with cache: 'reload' and matches offline
     with ignoreSearch.
  4. The registration script checks for an already-waiting worker and polls
     for new ones.

Signal origin: #105, #106.
"""

import re

import pytest
from fastapi.testclient import TestClient

from deadrop import api
from deadrop.api import app

SW_SOURCE = (api.STATIC_DIR / "sw.js").read_text()


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def shell(client) -> str:
    response = client.get("/app")
    assert response.status_code == 200
    return response.text


# --- Build identity ---


def test_shell_carries_the_app_version_meta_tag(shell):
    match = re.search(r'<meta name="app-version" content="([^"]*)">', shell)
    assert match, "shell has no app-version meta tag"
    assert match.group(1) == api._app_version()
    assert match.group(1), "app-version meta tag is empty"


def test_app_version_is_non_empty():
    assert api._app_version()


def test_shell_has_a_version_badge_element(shell):
    assert 'class="vbadge"' in shell, "shell has no .vbadge element"


def test_version_literal_appears_only_in_the_meta_tag(shell):
    """The meta tag is the single source; nothing else hardcodes the version."""
    assert shell.count(api._app_version()) == 1


def test_app_version_falls_back_when_version_module_is_absent(monkeypatch):
    """A source tree that has not been built still renders."""
    import builtins

    real_import = builtins.__import__

    def _fail(name, *args, **kwargs):
        if name.endswith("_version"):
            raise ImportError("no generated version file")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _fail)
    assert api._app_version() == "unknown"


# --- Cache-Control on the PWA control documents ---


def test_manifest_is_always_revalidated(client):
    response = client.get("/manifest.webmanifest")
    assert response.status_code == 200
    cache_control = response.headers["cache-control"]
    assert cache_control == "no-cache"
    assert "max-age" not in cache_control


def test_service_worker_is_always_revalidated(client):
    response = client.get("/sw.js")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-cache"
    assert response.headers["service-worker-allowed"] == "/"


# --- Service worker source ---


def test_precache_bypasses_the_http_cache():
    assert "cache: 'reload'" in SW_SOURCE


def test_offline_match_ignores_the_version_query():
    assert "ignoreSearch" in SW_SOURCE


def test_precache_tolerates_a_single_missing_asset():
    """One 404 must not fail the whole install."""
    assert re.search(r"cache\.add\(.*\)\.catch\(", SW_SOURCE)


# --- Registration script ---


def test_registration_checks_for_an_already_waiting_worker(shell):
    assert "reg.waiting" in shell


def test_registration_polls_for_new_workers(shell):
    assert "reg.update" in shell
    assert "visibilitychange" in shell


def test_banner_messages_the_waiting_worker_not_the_controller(shell):
    """skipWaiting on the active worker is a no-op; only waiting responds."""
    assert not re.search(
        r"navigator\.serviceWorker\.controller\??\.postMessage\('skipWaiting'\)", shell
    )
    assert "postMessage('skipWaiting')" in shell
