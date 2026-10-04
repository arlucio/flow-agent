import json
from pathlib import Path


EXTENSION_DIR = Path(__file__).resolve().parents[2] / "flow-extension"


def test_manifest_allows_new_and_legacy_flow_pages():
    manifest = json.loads((EXTENSION_DIR / "manifest.json").read_text(encoding="utf-8"))

    assert "https://flow.google.com/*" in manifest["host_permissions"]
    assert "https://flow.google.com/*" in manifest["content_scripts"][0]["matches"]
    assert "https://flow.google.com/*" in manifest["web_accessible_resources"][0]["matches"]
    assert "https://labs.google/fx/tools/flow*" in manifest["content_scripts"][0]["matches"]


def test_background_uses_precise_flow_page_eligibility_and_shared_tab_patterns():
    source = (EXTENSION_DIR / "background.js").read_text(encoding="utf-8")

    assert "'https://flow.google.com/*'" in source
    assert "parsed.hostname === 'flow.google.com'" in source
    assert "parsed.hostname !== 'labs.google'" in source
    assert "return createdTab;" in source
    assert "url: '*://labs.google/*'" not in source
    assert source.count("url: FLOW_TAB_URLS") >= 3


def test_background_opens_captcha_capable_project_pages():
    source = (EXTENSION_DIR / "background.js").read_text(encoding="utf-8")

    # labs.google/fx/tools/flow redirects to the flow.google.com home page, which
    # never loads reCAPTCHA; only /project/<id> pages do.
    assert "const FLOW_URL = 'https://flow.google.com/';" in source
    assert "function isFlowProjectUrl(url)" in source
    assert "/^\\/project\\/[^/]+/" in source
    assert "https://flow.google.com/project/${encodeURIComponent(projectId)}" in source
    assert "tabs.filter((t) => isFlowProjectUrl(t.url))" in source
    assert "solveCaptcha(id, captchaAction, projectId)" in source


def test_background_refreshes_token_through_labs_handoff():
    source = (EXTENSION_DIR / "background.js").read_text(encoding="utf-8")

    # The ya29 bearer is only observable during the labs.google -> flow.google.com
    # redirect; reloading a flow.google.com tab does not re-capture it.
    assert "const TOKEN_URL = 'https://labs.google/fx/tools/flow';" in source
    assert "async function refreshTokenViaLabs()" in source
    assert source.count("await refreshTokenViaLabs()") >= 2
    assert "chrome.tabs.reload(tabs[0].id)" not in source


def test_extension_verifies_captcha_bridge_before_using_a_tab():
    background = (EXTENSION_DIR / "background.js").read_text(encoding="utf-8")
    content = (EXTENSION_DIR / "content.js").read_text(encoding="utf-8")
    injected = (EXTENSION_DIR / "injected.js").read_text(encoding="utf-8")

    # A tab matching a Flow URL is not enough: its bridge must answer a ping,
    # otherwise every request burns the content-script timeout.
    assert "async function bridgeAlive(tabId)" in background
    assert "if (!(await bridgeAlive(tab.id))) continue;" in background
    assert "type: 'PING_BRIDGE'" in background
    assert "msg.type !== 'PING_BRIDGE'" in content
    assert "'FLOW_AGENT_PING'" in injected and "'FLOW_AGENT_PONG'" in injected
    # GET_CAPTCHA is re-dispatched until injected.js answers; injected.js dedups.
    assert "setInterval(dispatch, 500)" in content
    assert "_captchaInFlight" in injected
    assert "grecaptcha execute timeout" in injected

