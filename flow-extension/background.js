/**
 * Flow Agent — Chrome Extension Background Service Worker
 *
 * Connects to local Python agent via WebSocket (agent runs WS server).
 * Captures bearer token, solves reCAPTCHA, proxies API calls through browser.
 */

importScripts('config.js');

// Keep the last '[Flow Agent]' console lines in chrome.storage.local (debugLog)
// so a stall can be diagnosed without the service-worker console, which is
// gone by the time anyone looks.
const DEBUG_LOG_MAX = 200;
let _debugLog = [];
let _debugLogFlush = null;
for (const level of ['log', 'warn', 'error']) {
  const original = console[level].bind(console);
  console[level] = (...args) => {
    original(...args);
    if (typeof args[0] !== 'string' || !args[0].startsWith('[Flow Agent]')) return;
    const line = args.map((a) => (typeof a === 'string' ? a : (a?.message ?? JSON.stringify(a)))).join(' ');
    _debugLog.push(`${new Date().toISOString()} ${level.toUpperCase()} ${line}`);
    if (_debugLog.length > DEBUG_LOG_MAX) _debugLog = _debugLog.slice(-DEBUG_LOG_MAX);
    if (!_debugLogFlush) {
      _debugLogFlush = setTimeout(() => {
        _debugLogFlush = null;
        chrome.storage.local.set({ debugLog: _debugLog }).catch(() => {});
      }, 250);
    }
  };
}

let callbackUrl = 'http://127.0.0.1:18011/api/ext/callback';
// NOTE: This is a browser-restricted public API key — safe to ship in extension bundles.
const API_KEY = 'AIzaSyBtrm0o5ab1c-Ec8ZuLcGt3oJAA5VWt3pY';

let ws = null;
let wsPingTimer = null;
let flowKey = null;
let callbackSecret = null;  // Auth secret for HTTP callback, received from server on WS connect
let httpConnected = false;
let httpPollTimer = null;
let httpPollIntervalMs = 1000;
let state = 'off'; // off | idle | running
let manualDisconnect = false;
let extensionClientId = '';
let connectedServerHost = CONFIG.DEFAULT_SERVER_HOST;

function stopWsPing() {
  if (wsPingTimer) {
    clearInterval(wsPingTimer);
    wsPingTimer = null;
  }
}

function normalizeCallbackUrl(value) {
  try {
    const raw = String(value || '').trim();
    const parsed = new URL(/^https?:\/\//i.test(raw) ? raw : `https://${raw}`);
    const local = /^(localhost|127\.0\.0\.1|192\.168\.|10\.)/.test(parsed.hostname);
    parsed.protocol = local ? 'http:' : 'https:';
    parsed.pathname = '/api/ext/callback';
    parsed.search = '';
    parsed.hash = '';
    return parsed.toString().replace(/\/$/, '');
  } catch {
    return 'http://127.0.0.1:18011/api/ext/callback';
  }
}
let metrics = {
  tokenCapturedAt: null,
  requestCount: 0,   // captcha-consuming requests only (gen image/video/upscale)
  successCount: 0,
  failedCount: 0,
  lastError: null,
};

// ─── URL → Log Type Classifier ─────────────────────────────

// Visible log types — only these appear in the request log
const _VISIBLE_TYPES = new Set(['GEN_IMG', 'GEN_VID', 'GEN_VID_REF', 'UPSCALE', 'TRACKING', 'URL_REFRESH']);

function _classifyApiUrl(url) {
  if (url.includes('uploadImage')) return 'UPLOAD';
  if (url.includes('batchGenerateImages')) return 'GEN_IMG';
  if (url.includes('UpsampleVideo')) return 'UPSCALE';
  if (url.includes('ReferenceImages')) return 'GEN_VID_REF';
  if (url.includes('batchAsyncGenerateVideo')) return 'GEN_VID';
  if (url.includes('batchCheckAsync')) return 'POLL';
  if (url.includes('upsampleImage')) return 'UPS_IMG';
  if (url.includes('/media/')) return 'MEDIA';
  if (url.includes('/credits')) return 'CREDITS';
  return 'API';
}

// ─── Request Log ────────────────────────────────────────────

let requestLog = [];

function addRequestLog(entry) {
  requestLog.unshift(entry);
  if (requestLog.length > 100) requestLog.pop();
  chrome.storage.local.set({ requestLog }).catch(() => {});
  broadcastRequestLog();
}

function updateRequestLog(id, updates) {
  const entry = requestLog.find((e) => e.id === id);
  if (entry) Object.assign(entry, updates);
  chrome.storage.local.set({ requestLog }).catch(() => {});
  broadcastRequestLog();
}

function broadcastRequestLog() {
  chrome.runtime.sendMessage({ type: 'REQUEST_LOG_UPDATE', log: requestLog }).catch(() => { });
}

// ─── Startup ────────────────────────────────────────────────

let initialization;
function ensureInitialized() {
  if (!initialization) initialization = init().catch((error) => {
    initialization = null;
    console.error('[Flow Agent] Initialization failed:', error);
  });
  return initialization;
}

chrome.runtime.onInstalled.addListener(ensureInitialized);
chrome.runtime.onStartup.addListener(ensureInitialized);
chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === 'reconnect') connectToAgent();
  if (alarm.name === 'keepAlive') keepAlive();
  if (alarm.name === 'flushOutbox') flushOutbox();
  if (alarm.name === 'closeIdleFlowTab') await closeIdleFlowTab();
});

async function init() {
  if (chrome.sidePanel?.setPanelBehavior) {
    try {
      await chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true });
    } catch (error) {
      console.warn('[Flow Agent] Side Panel click behavior unavailable:', error.message);
    }
  }
  await chrome.storage.local.remove('customServerIp');
  const data = await chrome.storage.local.get(['flowKey', 'metrics', 'callbackSecret', 'callbackUrl', 'requestLog']);
  if (data.flowKey) flowKey = data.flowKey;
  if (data.metrics) Object.assign(metrics, data.metrics);
  if (data.callbackSecret) callbackSecret = data.callbackSecret;
  if (data.callbackUrl) callbackUrl = normalizeCallbackUrl(data.callbackUrl);
  if (Array.isArray(data.requestLog)) requestLog = data.requestLog.slice(0, 100);
  await loadOutbox();
  connectToAgent();
  // 0.5 min is Chrome's minimum alarm period — anything lower is silently clamped.
  chrome.alarms.create('keepAlive', { periodInMinutes: 0.5 });
  // Retry any responses left undelivered by a previous worker lifetime.
  chrome.alarms.create('flushOutbox', { periodInMinutes: 0.5 });
  flushOutbox();
  ensureAuthCaptured().catch(() => {});
}

ensureInitialized();

// ─── Cookie / SAPISIDHASH Auth Helpers ──────────────────────

async function getSapisidCookie() {
  const names = ['SAPISID', '__Secure-1PAPISID', '__Secure-3PAPISID', 'APISID'];
  for (const name of names) {
    try {
      const c = await chrome.cookies.get({ url: 'https://flow.google.com', name });
      if (c?.value) return c.value;
    } catch {}
  }
  for (const name of names) {
    try {
      const c = await chrome.cookies.get({ url: 'https://google.com', name });
      if (c?.value) return c.value;
    } catch {}
  }
  return null;
}

async function computeSapisidHash(sapisid, origin = 'https://flow.google.com') {
  const time = Math.floor(Date.now() / 1000);
  const str = `${time} ${sapisid} ${origin}`;
  const encoder = new TextEncoder();
  const data = encoder.encode(str);
  const hashBuffer = await crypto.subtle.digest('SHA-1', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
  return `${time}_${hashHex}`;
}

async function getAuthHeader() {
  if (flowKey && flowKey.startsWith('ya29.')) {
    return `Bearer ${flowKey}`;
  }
  const sapisid = await getSapisidCookie();
  if (sapisid) {
    const hash = await computeSapisidHash(sapisid, 'https://flow.google.com');
    return `SAPISIDHASH ${hash}`;
  }
  return null;
}

async function ensureAuthCaptured() {
  if (flowKey && flowKey.startsWith('ya29.')) return true;
  const sapisid = await getSapisidCookie();
  if (sapisid) {
    flowKey = `sapisid_${sapisid.slice(0, 8)}`;
    metrics.tokenCapturedAt = Date.now();
    await chrome.storage.local.set({ flowKey, metrics });
    console.log('[Flow Agent] Active Google cookie auth (SAPISID) registered with agent');
    sendToAgent({ type: 'token_captured', flowKey, clientId: extensionClientId });
    return true;
  }
  return false;
}

if (chrome.cookies?.onChanged) {
  chrome.cookies.onChanged.addListener((changeInfo) => {
    if (['SAPISID', '__Secure-1PAPISID', '__Secure-3PAPISID'].includes(changeInfo.cookie?.name)) {
      ensureAuthCaptured().catch(() => {});
    }
  });
}

// ─── Token Capture ──────────────────────────────────────────

chrome.webRequest.onBeforeSendHeaders.addListener(
  (details) => {
    if (!details?.requestHeaders?.length) return;
    const authHeader = details.requestHeaders.find(
      (h) => h.name?.toLowerCase() === 'authorization',
    );
    const value = authHeader?.value || '';
    if (!value.startsWith('Bearer ya29.')) return;

    const token = value.replace(/^Bearer\s+/i, '').trim();
    if (!token) return;

    // Always update — even if same token string, refresh the timestamp
    flowKey = token;
    metrics.tokenCapturedAt = Date.now();
    chrome.storage.local.set({ flowKey, metrics });
    console.log('[Flow Agent] Bearer token captured');

    // Notify whichever transport is active.
    sendToAgent({ type: 'token_captured', flowKey, clientId: extensionClientId });
  },
  { urls: ['https://aisandbox-pa.googleapis.com/*', 'https://*.googleapis.com/*', 'https://labs.google/*', 'https://flow.google.com/*'] },
  ['requestHeaders', 'extraHeaders'],
);

let _openingFlowTab = false;

// ─── On-demand tab lifecycle ────────────────────────────────
// Open the Flow tab only when real work needs it (token capture or captcha).
// Keep it available in the background so user tabs are never redirected.
const FLOW_TAB_URLS = [
  'https://flow.google.com/*',
  'https://labs.google/fx/tools/flow*',
  'https://labs.google/fx/*/tools/flow*',
];
// labs.google/fx/tools/flow now 301s to the flow.google.com home page, which never
// loads reCAPTCHA Enterprise — only /project/<id> pages do. Land there directly.
const FLOW_URL = 'https://flow.google.com/';
let workTabId = null;
let flowTabOpening = null;
let workTabCreatedByExtension = false;
let lastFlowProjectUrl = null;

chrome.storage.local.get(['lastFlowProjectUrl']).then((data) => {
  if (!lastFlowProjectUrl && isFlowProjectUrl(data.lastFlowProjectUrl)) {
    lastFlowProjectUrl = data.lastFlowProjectUrl;
  }
}).catch(() => {});

// Remember the most recent project page any tab visits so an on-demand tab can
// open somewhere captcha-capable even when the request carries no projectId.
chrome.tabs.onUpdated.addListener((_, changeInfo) => {
  if (changeInfo.url && isFlowProjectUrl(changeInfo.url)) {
    lastFlowProjectUrl = changeInfo.url;
    chrome.storage.local.set({ lastFlowProjectUrl }).catch(() => {});
  }
});

function isFlowProjectUrl(url) {
  if (!url) return false;
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'https:' && parsed.hostname === 'flow.google.com'
      && /^\/project\/[^/]+/.test(parsed.pathname);
  } catch {
    return false;
  }
}

function flowTabTargetUrl(projectId) {
  if (projectId) return `https://flow.google.com/project/${encodeURIComponent(projectId)}`;
  return lastFlowProjectUrl || FLOW_URL;
}

// Google only sends the ya29 bearer while labs.google/fx/tools/flow hands off to
// flow.google.com; reloading a flow.google.com page never surfaces it.
const TOKEN_URL = 'https://labs.google/fx/tools/flow';

// Drive a tab through the labs.google handoff so the webRequest listener can
// capture a fresh bearer. Never navigates a tab the user opened.
async function refreshTokenViaLabs() {
  let tabId = null;
  if (workTabId !== null && workTabCreatedByExtension) {
    try {
      await chrome.tabs.get(workTabId);
      tabId = workTabId;
    } catch {
      workTabId = null;
    }
  }
  if (tabId === null) {
    const tab = await chrome.tabs.create({ url: TOKEN_URL, active: false });
    workTabId = tab.id;
    workTabCreatedByExtension = true;
    tabId = tab.id;
  } else {
    await chrome.tabs.update(tabId, { url: TOKEN_URL });
  }
  await waitForTabComplete(tabId);
  scheduleFlowTabClose();
  return tabId;
}

function scheduleFlowTabClose() {
  if (workTabCreatedByExtension) {
    chrome.alarms.create('closeIdleFlowTab', { delayInMinutes: 2 });
  }
}

async function closeIdleFlowTab() {
  if (!workTabId || !workTabCreatedByExtension) return;
  if (state === 'running') {
    scheduleFlowTabClose();
    return;
  }
  const tabId = workTabId;
  workTabId = null;
  workTabCreatedByExtension = false;
  try {
    await chrome.tabs.remove(tabId);
  } catch { /* tab was already closed */ }
}

function isFlowUrl(url) {
  if (!url) return false;
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:') return false;
    if (parsed.hostname === 'flow.google.com') return true;
    if (parsed.hostname !== 'labs.google') return false;
    return /^\/fx\/(?:[^/]+\/)?tools\/flow(?:\/|$)/.test(parsed.pathname);
  } catch {
    return false;
  }
}

async function waitForTabComplete(tabId, maxWaitMs = 10000) {
  return new Promise((resolve) => {
    const start = Date.now();
    function listener(updatedTabId, changeInfo, tab) {
      if (updatedTabId === tabId && changeInfo.status === 'complete') {
        chrome.tabs.onUpdated.removeListener(listener);
        resolve(tab);
      }
    }
    chrome.tabs.onUpdated.addListener(listener);
    setTimeout(() => {
      chrome.tabs.onUpdated.removeListener(listener);
      chrome.tabs.get(tabId).then(resolve).catch(() => resolve(null));
    }, maxWaitMs);
  });
}

// Every await on the tab-lookup path is bounded: one Chrome API call that never
// settles would otherwise park getOrOpenFlowTab's shared promise forever and
// silently stall every later request behind it.
function withTimeout(promise, ms, label) {
  let timer;
  const deadline = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label}_TIMEOUT`)), ms);
  });
  return Promise.race([promise, deadline]).finally(() => clearTimeout(timer));
}

// True only if content.js AND injected.js answer in this tab. A tab can match a
// Flow URL yet have a dead bridge (opened before an extension reload, discarded,
// or on a page that never loaded injected.js) — sending it GET_CAPTCHA then just
// burns 25s and reports CONTENT_TIMEOUT.
async function bridgeAlive(tabId) {
  const ping = () => withTimeout(chrome.tabs.sendMessage(tabId, { type: 'PING_BRIDGE' }), 5000, 'PING');
  try {
    const resp = await ping();
    if (resp?.ok) return true;
  } catch { /* no content script yet — inject and retry below */ }
  try {
    const tab = await chrome.tabs.get(tabId);
    if (!isFlowUrl(tab?.url)) return false;
    await withTimeout(
      chrome.scripting.executeScript({ target: { tabId }, files: ['content.js'] }),
      10000, 'INJECT',
    );
    await sleep(300);
    const resp = await ping();
    return !!resp?.ok;
  } catch (e) {
    console.warn('[Flow Agent] Bridge ping failed for tab', tabId, e.message);
    return false;
  }
}

// Finds/wakes/creates the Flow tab. Returns
// the tab, or null if it couldn't be opened.
async function _getOrOpenFlowTab(projectId) {
  const targetUrl = flowTabTargetUrl(projectId);

  if (workTabId !== null) {
    try {
      let tab = await chrome.tabs.get(workTabId);
      // Never navigate or cache a user's non-project tab, even if its bridge
      // answers. Home pages do not load reCAPTCHA.
      if (!workTabCreatedByExtension && !isFlowProjectUrl(tab?.url)) {
        console.warn('[Flow Agent] User work tab is not on a /project/ page; forgetting it');
        workTabId = null;
      } else {
        const needsProjectPage = workTabCreatedByExtension && !isFlowProjectUrl(tab?.url);
        if (tab && needsProjectPage) {
          await withTimeout(chrome.tabs.update(workTabId, { url: targetUrl }), 10000, 'TAB_UPDATE');
          await waitForTabComplete(workTabId);
          tab = await chrome.tabs.get(workTabId);
        }
        if (await bridgeAlive(workTabId)) {
          scheduleFlowTabClose();
          return tab;
        }
        console.warn('[Flow Agent] Flow tab', workTabId, 'has a dead captcha bridge; looking for another');
        workTabId = null;
      }
    } catch (e) {
      workTabId = null; // closed by the user — fall through and open fresh
    }
  }

  const tabs = await chrome.tabs.query({ url: FLOW_TAB_URLS });
  // Project pages first — they are the only ones that load reCAPTCHA.
  const candidates = [...tabs.filter((t) => isFlowProjectUrl(t.url)), ...tabs.filter((t) => !isFlowProjectUrl(t.url))];
  for (const tab of candidates) {
    if (!isFlowProjectUrl(tab.url)) {
      console.warn('[Flow Agent] Flow tab is not on a /project/ page; reCAPTCHA is only available there');
      if (isFlowProjectUrl(targetUrl)) continue;
    }
    if (!(await bridgeAlive(tab.id))) continue;
    workTabId = tab.id;
    workTabCreatedByExtension = false;
    return tab;
  }
  if (tabs.length) {
    console.warn('[Flow Agent] None of', tabs.length, 'eligible Flow tab(s) answered the bridge ping; opening a fresh one');
  }

  const createdTab = await withTimeout(chrome.tabs.create({ url: targetUrl, active: false }), 10000, 'TAB_CREATE');
  workTabId = createdTab.id;
  workTabCreatedByExtension = true;
  console.log('[Flow Agent] Opened Flow work tab', workTabId, 'at', targetUrl);
  await waitForTabComplete(workTabId);
  await sleep(1500);

  // Inject content script to make sure reCAPTCHA bridge is ready
  try {
    const readyTab = await chrome.tabs.get(workTabId);
    if (!isFlowUrl(readyTab?.url)) throw new Error('INVALID_FLOW_TAB');
    await withTimeout(chrome.scripting.executeScript({
      target: { tabId: workTabId },
      files: ['content.js'],
    }), 10000, 'INJECT');
  } catch (e) {
    console.warn('[Flow Agent] Content script pre-injection:', e.message);
  }

  scheduleFlowTabClose();
  return createdTab;
}

async function getOrOpenFlowTab(projectId) {
  if (flowTabOpening) return flowTabOpening;
  flowTabOpening = withTimeout(_getOrOpenFlowTab(projectId), 60000, 'FLOW_TAB')
    .catch((e) => {
      console.error('[Flow Agent] getOrOpenFlowTab failed:', e.message);
      return null;
    });
  try {
    return await flowTabOpening;
  } finally {
    flowTabOpening = null;
  }
}

async function getAnyFlowTab() {
  try {
    const tabs = await chrome.tabs.query({ url: FLOW_TAB_URLS });
    if (!tabs || !tabs.length) return null;
    const projectTab = tabs.find((t) => isFlowProjectUrl(t.url));
    return projectTab || tabs[0];
  } catch {
    return null;
  }
}

// Generation needs a /project/<id> page — that's the only place the prompt
// editor and reCAPTCHA exist. If the best available tab is the Flow home page,
// dismiss the cookie bar and click "New project" to land on one.
async function ensureProjectPage(tab) {
  if (!tab) return null;
  if (isFlowProjectUrl(tab.url)) return tab;
  try {
    const results = await withTimeout(
      chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: () => {
          // Cookie/consent bars can swallow the real click — clear them first.
          const consent = Array.from(document.querySelectorAll('button')).find(b =>
            /^(agree|accept|no thanks|reject)$/i.test((b.innerText || '').trim()));
          if (consent) consent.click();
          const btn = Array.from(document.querySelectorAll('button')).find(b =>
            /new\s*project/i.test(b.innerText || '') || /new project/i.test(b.getAttribute('aria-label') || ''));
          if (!btn) return { ok: false, error: 'NO_NEW_PROJECT_BUTTON' };
          btn.click();
          return { ok: true };
        },
      }),
      10000,
      'ENSURE_PROJECT',
    );
    if (!results?.[0]?.result?.ok) {
      console.warn('[Flow Agent] ensureProjectPage:', results?.[0]?.result?.error);
      return null;
    }
    for (let i = 0; i < 40; i++) {
      await sleep(500);
      try {
        const t = await chrome.tabs.get(tab.id);
        if (isFlowProjectUrl(t?.url)) return t;
      } catch {
        return null;
      }
    }
    console.warn('[Flow Agent] ensureProjectPage: tab never navigated to /project/');
    return null;
  } catch (e) {
    console.warn('[Flow Agent] ensureProjectPage failed:', e.message);
    return null;
  }
}

// Token is considered fresh if it exists and was captured less than 50 minutes ago.
// Google OAuth tokens expire after ~60 min, so 50 min gives a safe buffer.
// Cookie (SAPISID) auth is long-lived and fresh as long as the user is signed in.
function isTokenFresh() {
  if (!flowKey) return false;
  if (flowKey.startsWith('sapisid_')) return true;
  if (!metrics.tokenCapturedAt) return false;
  const ageMs = Date.now() - metrics.tokenCapturedAt;
  return ageMs < 50 * 60 * 1000; // 50 minutes
}

async function captureTokenFromFlowTab() {
  // Skip if token is still fresh — no need to open/refresh anything
  if (isTokenFresh()) {
    console.log('[Flow Agent] Token still fresh, skipping tab refresh');
    return;
  }

  if (await ensureAuthCaptured()) {
    console.log('[Flow Agent] Cookie auth captured, skipping tab refresh');
    return;
  }

  if (_openingFlowTab) {
    console.log('[Flow Agent] Flow tab already opening, skipping');
    return;
  }
  _openingFlowTab = true;
  try {
    const tabId = await refreshTokenViaLabs();
    console.log('[Flow Agent] Token refresh triggered via labs.google handoff in tab', tabId);
  } catch (e) {
    console.error('[Flow Agent] Token refresh failed:', e);
  } finally {
    _openingFlowTab = false;
  }
}


// ─── WebSocket to Agent ─────────────────────────────────────

async function connectToAgent() {
  if (manualDisconnect) return;
  await connectHttpAgent();
  if (ws?.readyState === WebSocket.CONNECTING) return;
  if (ws?.readyState === WebSocket.OPEN) return;

  const data = await chrome.storage.local.get(['clientId']);
  const serverIp = CONFIG.DEFAULT_SERVER_HOST;
  connectedServerHost = serverIp;
  const isLocal = /^(127\.0\.0\.1|localhost|192\.168\.|10\.)/.test(serverIp);
  const wsScheme = isLocal ? 'ws' : 'wss';
  const httpScheme = isLocal ? 'http' : 'https';
  const wsUrl = `${wsScheme}://${serverIp}/ws`;

  // Dynamically resolve callbackUrl
  callbackUrl = `${httpScheme}://${serverIp}/api/ext/callback`;

  try {
    ws = new WebSocket(wsUrl);
  } catch (e) {
    console.error('[Flow Agent] WS connect error:', e);
    scheduleReconnect();
    return;
  }

  ws.onopen = async () => {
    console.log('[Flow Agent] Connected to agent: ' + wsUrl);
    chrome.alarms.clear('reconnect');
    setState('idle');

    const storage = await chrome.storage.local.get(['clientId']);
    let clientId = storage.clientId;
    if (!clientId) {
      const prefix = CONFIG.DEFAULT_CLIENT_ID_PREFIX || 'client';
      clientId = `${prefix}-${Math.random().toString(36).substring(2, 8)}`;
      await chrome.storage.local.set({ clientId });
    }
    extensionClientId = clientId;
    await ensureAuthCaptured();

    // Send current state + resend token if we have one, along with clientId
    ws.send(JSON.stringify({
      type: 'extension_ready',
      clientId: clientId,
      flowKeyPresent: !!flowKey,
      tokenAge: flowKey && metrics.tokenCapturedAt ? Date.now() - metrics.tokenCapturedAt : null,
    }));
    if (flowKey) {
      ws.send(JSON.stringify({
        type: 'token_captured',
        clientId: clientId,
        flowKey: flowKey
      }));
    }
    // Backend is reachable again — push any responses queued while it was down.
    flushOutbox();

    // MV3 kills an idle service worker after ~30s, which drops the socket and
    // causes a reconnect → token-refresh-request storm on the backend. A ping
    // every 25s keeps the worker (and socket) alive between alarm periods.
    stopWsPing();
    wsPingTimer = setInterval(() => {
      if (ws?.readyState === WebSocket.OPEN) {
        try { ws.send(JSON.stringify({ type: 'ping' })); } catch { }
      }
    }, 25000);
  };

  ws.onmessage = async ({ data }) => {
    try {
      const msg = JSON.parse(data);

      if (msg.method === 'api_request') {
        await handleApiRequest(msg);
      } else if (msg.method === 'get_media_url') {
        await handleGetMediaUrl(msg);
      } else if (msg.method === 'trpc_request') {
        await handleTrpcRequest(msg);
      } else if (msg.method === 'upload_video') {
        await handleUploadVideo(msg);
      } else if (msg.method === 'solve_captcha') {
        await handleSolveCaptcha(msg);
      } else if (msg.method === 'get_status') {
        sendToAgent({
          id: msg.id,
          result: {
            state,
            flowKeyPresent: !!flowKey,
            manualDisconnect,
            tokenAge: metrics.tokenCapturedAt ? Date.now() - metrics.tokenCapturedAt : null,
            metrics,
          },
        });
      } else if (msg.method === 'reload_extension') {
        console.log('[Flow Agent] Reloading extension via command...');
        chrome.runtime.reload();
      } else if (msg.method === 'reload_tabs') {
        const tabs = await chrome.tabs.query({ url: FLOW_TAB_URLS });
        for (const t of tabs) {
          try { await chrome.tabs.reload(t.id); } catch {}
        }
        sendToAgent({ id: msg.id, result: { reloadedTabs: tabs.length } });
      } else if (msg.method === 'run_probe') {
        try {
          if (msg.params?.probeType === 'test_labs_nav') {
            const captured = [];
            const listener = (details) => {
              const auth = details.requestHeaders?.find(h => h.name.toLowerCase() === 'authorization');
              captured.push({
                url: details.url,
                method: details.method,
                authHeader: auth ? auth.value.slice(0, 30) : null
              });
            };
            chrome.webRequest.onBeforeSendHeaders.addListener(
              listener,
              { urls: ['<all_urls>'] },
              ['requestHeaders', 'extraHeaders']
            );
            const tab = await chrome.tabs.create({ url: 'https://labs.google/fx/tools/flow', active: false });
            await sleep(7000);
            chrome.webRequest.onBeforeSendHeaders.removeListener(listener);
            let finalTabUrl = null;
            try {
              const t = await chrome.tabs.get(tab.id);
              finalTabUrl = t?.url;
              await chrome.tabs.remove(tab.id);
            } catch {}
            sendToAgent({
              id: msg.id,
              result: {
                finalTabUrl,
                capturedUrlsCount: captured.length,
                authCaptured: captured.filter(c => c.authHeader),
                relevantRequests: captured.filter(c => c.url.includes('google') || c.url.includes('token') || c.url.includes('api')).slice(0, 30)
              }
            });
            return;
          }
          if (msg.params?.probeType === 'list_tabs') {
            const allTabs = await chrome.tabs.query({});
            sendToAgent({
              id: msg.id,
              result: {
                tabs: allTabs.map(t => ({ id: t.id, url: t.url, title: t.title, active: t.active }))
              }
            });
            return;
          }
          if (msg.params?.probeType === 'inspect_toolbar') {
            const tab = (await getAnyFlowTab()) || (await getOrOpenFlowTab());
            if (!tab) {
              sendToAgent({ id: msg.id, error: 'NO_FLOW_TAB' });
              return;
            }
            const results = await chrome.scripting.executeScript({
              target: { tabId: tab.id },
              world: 'MAIN',
              func: () => {
                const buttons = Array.from(document.querySelectorAll('button')).map(b => ({
                  text: b.innerText?.trim().replace(/\n/g, ' '),
                  aria: b.getAttribute('aria-label'),
                  classes: b.className
                }));
                return { buttons };
              }
            });
            sendToAgent({ id: msg.id, result: results?.[0]?.result });
            return;
          }
          if (msg.params?.probeType === 'inspect_dom') {
            // Full interactive-element dump for building selectors on a new
            // frontend build: buttons, menus, textboxes, selects, overlays.
            const tab = (await getAnyFlowTab()) || (await getOrOpenFlowTab());
            if (!tab) {
              sendToAgent({ id: msg.id, error: 'NO_FLOW_TAB' });
              return;
            }
            const results = await chrome.scripting.executeScript({
              target: { tabId: tab.id },
              world: 'MAIN',
              func: () => {
                const pick = (el) => ({
                  tag: el.tagName.toLowerCase(),
                  text: (el.innerText || '').trim().replace(/\n/g, ' | ').slice(0, 90),
                  aria: el.getAttribute('aria-label'),
                  role: el.getAttribute('role'),
                  cls: (typeof el.className === 'string' ? el.className : '').split(/\s+/).filter(c => c && !c.startsWith('mat-') && !c.startsWith('mdc-')).slice(0, 4).join('.'),
                  disabled: !!el.disabled,
                  testid: el.getAttribute('data-testid') || el.getAttribute('data-id'),
                });
                const buttons = Array.from(document.querySelectorAll('button, [role="button"]')).map(pick);
                const textboxes = Array.from(document.querySelectorAll('[contenteditable], [role="textbox"], textarea, .ProseMirror')).map(pick);
                const menus = Array.from(document.querySelectorAll('[role="listbox"], [role="menu"], mat-select, [aria-haspopup]')).map(pick);
                const overlays = Array.from(document.querySelectorAll('.cdk-overlay-container *, mat-bottom-sheet-container, mat-dialog-container')).slice(0, 30).map(pick);
                return {
                  url: location.href,
                  buttons: buttons.filter(b => b.text || b.aria),
                  textboxes, menus, overlays,
                };
              },
            });
            sendToAgent({ id: msg.id, result: results?.[0]?.result });
            return;
          }
          if (msg.params?.probeType === 'open_settings') {
            // Click the generation-settings trigger, then dump the overlay
            // menu so we can map mode/model/aspect options to selectors.
            const tab = (await getAnyFlowTab()) || (await getOrOpenFlowTab());
            if (!tab) {
              sendToAgent({ id: msg.id, error: 'NO_FLOW_TAB' });
              return;
            }
            const results = await chrome.scripting.executeScript({
              target: { tabId: tab.id },
              world: 'MAIN',
              func: async () => {
                const trigger = document.querySelector('.settings-trigger-button')
                  || Array.from(document.querySelectorAll('button,[role="button"]'))
                       .find(b => b.getAttribute('aria-label') === 'Settings trigger');
                if (!trigger) return { error: 'NO_SETTINGS_TRIGGER' };
                trigger.click();
                await new Promise(r => setTimeout(r, 900));
                const pick = (el) => ({
                  tag: el.tagName.toLowerCase(),
                  text: (el.innerText || '').trim().replace(/\n/g, ' | ').slice(0, 110),
                  aria: el.getAttribute('aria-label'),
                  role: el.getAttribute('role'),
                  cls: (typeof el.className === 'string' ? el.className : '').split(/\s+/).filter(Boolean).slice(0, 5).join('.'),
                });
                const overlayRoot = document.querySelector('.cdk-overlay-container, mat-bottom-sheet-container, mat-dialog-container');
                const items = overlayRoot
                  ? Array.from(overlayRoot.querySelectorAll('button, [role="menuitem"], [role="option"], [role="radio"], [role="switch"], mat-option, li, [role="menuitemradio"]')).map(pick)
                  : [];
                const groups = overlayRoot
                  ? Array.from(overlayRoot.querySelectorAll('[role="group"], [role="radiogroup"], fieldset, h1,h2,h3,h4, [class*="label"], [class*="header"], [class*="title"]')).map(pick).filter(p => p.text)
                  : [];
                return { overlayText: (overlayRoot?.innerText || '').trim().slice(0, 2000), items, groups };
              },
            });
            sendToAgent({ id: msg.id, result: results?.[0]?.result });
            return;
          }
          if (msg.params?.probeType === 'open_model_menu') {
            // Open settings → "Select model family" and dump the model menu
            // (Veo / Nano Banana / Imagen options on the new frontend).
            const tab = (await getAnyFlowTab()) || (await getOrOpenFlowTab());
            if (!tab) {
              sendToAgent({ id: msg.id, error: 'NO_FLOW_TAB' });
              return;
            }
            const results = await chrome.scripting.executeScript({
              target: { tabId: tab.id },
              world: 'MAIN',
              func: async () => {
                const overlayQ = '.cdk-overlay-container button, .cdk-overlay-container [role="button"]';
                const findModelBtn = () => Array.from(document.querySelectorAll(overlayQ))
                  .find(b => b.getAttribute('aria-label') === 'Select model family' || b.innerText?.includes('arrow_drop_down'));
                let modelBtn = findModelBtn();
                if (!modelBtn) {
                  const trigger = document.querySelector('.settings-trigger-button');
                  if (!trigger) return { error: 'NO_SETTINGS_TRIGGER' };
                  trigger.click();
                  await new Promise(r => setTimeout(r, 900));
                  modelBtn = findModelBtn();
                }
                if (!modelBtn) return { error: 'NO_MODEL_BUTTON', overlayText: document.querySelector('.cdk-overlay-container')?.innerText?.slice(0, 500) };
                modelBtn.click();
                await new Promise(r => setTimeout(r, 900));
                const pick = (el) => ({
                  tag: el.tagName.toLowerCase(),
                  text: (el.innerText || '').trim().replace(/\n/g, ' | ').slice(0, 110),
                  aria: el.getAttribute('aria-label'),
                  role: el.getAttribute('role'),
                  cls: (typeof el.className === 'string' ? el.className : '').split(/\s+/).filter(Boolean).slice(0, 4).join('.'),
                });
                const overlays = Array.from(document.querySelectorAll('.cdk-overlay-container .cdk-overlay-pane, .cdk-overlay-container [role="menu"], .cdk-overlay-container [role="listbox"], mat-bottom-sheet-container'));
                const last = overlays[overlays.length - 1] || document.querySelector('.cdk-overlay-container');
                const items = last ? Array.from(last.querySelectorAll('button, [role="menuitem"], [role="menuitemradio"], [role="option"], mat-option, li, a')).map(pick).filter(p => p.text || p.aria) : [];
                return { overlayCount: overlays.length, menuText: (last?.innerText || '').trim().slice(0, 2000), items };
              },
            });
            sendToAgent({ id: msg.id, result: results?.[0]?.result });
            return;
          }
          if (msg.params?.probeType === 'find_mode_switch') {
            // Locate the generation-mode control (Text-to-Image vs Video etc.)
            // by scanning the prompt-box subtree and the whole doc for
            // 'Video'/'Image'/'Text to' labelled controls.
            const tab = (await getAnyFlowTab()) || (await getOrOpenFlowTab());
            if (!tab) {
              sendToAgent({ id: msg.id, error: 'NO_FLOW_TAB' });
              return;
            }
            const results = await chrome.scripting.executeScript({
              target: { tabId: tab.id },
              world: 'MAIN',
              func: () => {
                const pick = (el) => ({
                  tag: el.tagName.toLowerCase(),
                  text: (el.innerText || '').trim().replace(/\n/g, ' | ').slice(0, 100),
                  aria: el.getAttribute('aria-label'),
                  role: el.getAttribute('role'),
                  cls: (typeof el.className === 'string' ? el.className : '').split(/\s+/).filter(Boolean).slice(0, 4).join('.'),
                });
                // everything whose own text mentions mode-ish words
                const modeish = [];
                for (const el of document.querySelectorAll('button, [role="button"], [role="tab"], [role="combobox"], mat-select, [aria-haspopup], .cdk-overlay-container *')) {
                  const t = (el.innerText || '').trim();
                  const a = el.getAttribute('aria-label') || '';
                  if (/video|image|veo|banana|imagen|frame|ingredient|text to/i.test(t + ' ' + a) && t.length < 120) {
                    modeish.push(pick(el));
                  }
                }
                // prompt box ancestors
                const pm = document.querySelector('.ProseMirror');
                const ancestors = [];
                let n = pm;
                for (let i = 0; n && i < 6; i++, n = n.parentElement) {
                  ancestors.push({ tag: n.tagName.toLowerCase(), cls: (typeof n.className === 'string' ? n.className : '').split(/\s+/).filter(Boolean).slice(0, 6).join('.'), text: (n.innerText || '').trim().replace(/\n/g, ' | ').slice(0, 200) });
                }
                return { modeish: modeish.slice(0, 40), ancestors };
              },
            });
            sendToAgent({ id: msg.id, result: results?.[0]?.result });
            return;
          }
          if (msg.params?.probeType === 'open_tune') {
            // Close any open overlay, then open the prompt-box "tune"/Settings
            // button — candidate location for the image/video mode switch.
            const tab = (await getAnyFlowTab()) || (await getOrOpenFlowTab());
            if (!tab) {
              sendToAgent({ id: msg.id, error: 'NO_FLOW_TAB' });
              return;
            }
            const results = await chrome.scripting.executeScript({
              target: { tabId: tab.id },
              world: 'MAIN',
              func: async () => {
                document.body.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', code: 'Escape', bubbles: true }));
                await new Promise(r => setTimeout(r, 500));
                document.body.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', code: 'Escape', bubbles: true }));
                await new Promise(r => setTimeout(r, 500));
                const pick = (el) => ({
                  tag: el.tagName.toLowerCase(),
                  text: (el.innerText || '').trim().replace(/\n/g, ' | ').slice(0, 110),
                  aria: el.getAttribute('aria-label'),
                  role: el.getAttribute('role'),
                  cls: (typeof el.className === 'string' ? el.className : '').split(/\s+/).filter(Boolean).slice(0, 4).join('.'),
                });
                const tuneBtn = Array.from(document.querySelectorAll('button'))
                  .find(b => b.getAttribute('aria-label') === 'Settings' && b.closest('flow-base-prompt-box, .base-prompt-box'));
                if (!tuneBtn) return { error: 'NO_TUNE_BUTTON' };
                tuneBtn.click();
                await new Promise(r => setTimeout(r, 900));
                const overlayRoot = document.querySelector('.cdk-overlay-container');
                const items = overlayRoot
                  ? Array.from(overlayRoot.querySelectorAll('button, [role="menuitem"], [role="option"], [role="radio"], [role="switch"], [role="tab"], mat-option, li')).map(pick).filter(p => p.text || p.aria)
                  : [];
                return { overlayText: (overlayRoot?.innerText || '').trim().slice(0, 2000), items };
              },
            });
            sendToAgent({ id: msg.id, result: results?.[0]?.result });
            return;
          }
          if (msg.params?.probeType === 'open_video_model') {
            // Session drawer → "Video generation default model" menu — lists
            // the Veo/Omni variants available on this account.
            const tab = (await getAnyFlowTab()) || (await getOrOpenFlowTab());
            if (!tab) {
              sendToAgent({ id: msg.id, error: 'NO_FLOW_TAB' });
              return;
            }
            const results = await chrome.scripting.executeScript({
              target: { tabId: tab.id },
              world: 'MAIN',
              func: async () => {
                const pick = (el) => ({
                  tag: el.tagName.toLowerCase(),
                  text: (el.innerText || '').trim().replace(/\n/g, ' | ').slice(0, 110),
                  aria: el.getAttribute('aria-label'),
                  role: el.getAttribute('role'),
                  cls: (typeof el.className === 'string' ? el.className : '').split(/\s+/).filter(Boolean).slice(0, 4).join('.'),
                });
                const dumpOverlays = () => Array.from(document.querySelectorAll('.cdk-overlay-container [role="menu"], .cdk-overlay-container [role="listbox"], .cdk-overlay-container .cdk-overlay-pane'))
                  .map(p => ({ text: (p.innerText || '').trim().slice(0, 800), items: Array.from(p.querySelectorAll('button,[role="menuitem"],[role="option"],flow-menu-item')).map(pick).filter(x => x.text || x.aria) }));
                const vidBtn = document.querySelector('.video-model-picker-button')
                  || Array.from(document.querySelectorAll('button')).find(b => b.getAttribute('aria-label') === 'Video generation default model');
                if (!vidBtn) {
                  // drawer may be closed — reopen via tune button
                  const tuneBtn = Array.from(document.querySelectorAll('button'))
                    .find(b => b.getAttribute('aria-label') === 'Settings' && b.closest('flow-base-prompt-box, .base-prompt-box'));
                  if (!tuneBtn) return { error: 'NO_TUNE_OR_VIDEO_BTN' };
                  tuneBtn.click();
                  await new Promise(r => setTimeout(r, 900));
                }
                const vb = document.querySelector('.video-model-picker-button')
                  || Array.from(document.querySelectorAll('button')).find(b => b.getAttribute('aria-label') === 'Video generation default model');
                if (!vb) return { error: 'NO_VIDEO_MODEL_BTN' };
                vb.click();
                await new Promise(r => setTimeout(r, 900));
                return { overlays: dumpOverlays() };
              },
            });
            sendToAgent({ id: msg.id, result: results?.[0]?.result });
            return;
          }
          if (msg.params?.probeType === 'new_session_menu') {
            // Close the settings drawer if open (header Close/Back), then click
            // "Start new session" and dump whatever appears — the session type
            // picker (image vs video) likely lives there.
            const tab = (await getAnyFlowTab()) || (await getOrOpenFlowTab());
            if (!tab) {
              sendToAgent({ id: msg.id, error: 'NO_FLOW_TAB' });
              return;
            }
            const results = await chrome.scripting.executeScript({
              target: { tabId: tab.id },
              world: 'MAIN',
              func: async () => {
                const pick = (el) => ({
                  tag: el.tagName.toLowerCase(),
                  text: (el.innerText || '').trim().replace(/\n/g, ' | ').slice(0, 110),
                  aria: el.getAttribute('aria-label'),
                  role: el.getAttribute('role'),
                  cls: (typeof el.className === 'string' ? el.className : '').split(/\s+/).filter(Boolean).slice(0, 4).join('.'),
                });
                const byAria = (l) => Array.from(document.querySelectorAll('button')).find(b => b.getAttribute('aria-label') === l);
                // close drawer/sub-view if present (header Close or Back)
                for (const label of ['Close', 'Back']) {
                  const c = Array.from(document.querySelectorAll('button.header-action'))
                    .find(b => b.getAttribute('aria-label') === label);
                  if (c) { c.click(); await new Promise(r => setTimeout(r, 700)); }
                }
                document.body.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', code: 'Escape', bubbles: true }));
                await new Promise(r => setTimeout(r, 400));
                const btn = byAria('Start new session');
                if (!btn) return { error: 'NO_NEW_SESSION_BTN' };
                btn.click();
                await new Promise(r => setTimeout(r, 1400));
                const dialogs = Array.from(document.querySelectorAll('.cdk-overlay-container .cdk-overlay-pane, mat-dialog-container, [role="dialog"], .cdk-overlay-container [role="menu"], .cdk-overlay-container [role="listbox"]'));
                const dumps = dialogs.map(d => ({
                  cls: (typeof d.className === 'string' ? d.className : '').split(/\s+/).filter(Boolean).slice(0, 4).join('.'),
                  text: (d.innerText || '').trim().slice(0, 900),
                  items: Array.from(d.querySelectorAll('button,[role="menuitem"],[role="option"],flow-menu-item,[role="radio"],[role="tab"]')).map(pick).filter(x => x.text || x.aria),
                }));
                // also dump suggestion cards & current header actions in case the
                // session list changed inline rather than via dialog
                const cards = Array.from(document.querySelectorAll('.suggestion-card, flow-session-item, [class*="session"]')).map(pick).filter(x => x.text).slice(0, 20);
                const headerBtns = Array.from(document.querySelectorAll('button.header-action, button.flow-icon-button-transparent')).map(pick).filter(x => x.text || x.aria);
                return { url: location.href, dialogs: dumps, cards, headerBtns };
              },
            });
            sendToAgent({ id: msg.id, result: results?.[0]?.result });
            return;
          }
          if (msg.params?.probeType === 'screenshot') {
            // Capture the Flow tab as PNG → base64 data URL for visual debug.
            const tab = (await getAnyFlowTab()) || (await getOrOpenFlowTab());
            if (!tab) {
              sendToAgent({ id: msg.id, error: 'NO_FLOW_TAB' });
              return;
            }
            try {
              await chrome.tabs.update(tab.id, { active: true });
              await new Promise(r => setTimeout(r, 600));
              const dataUrl = await chrome.tabs.captureVisibleTab(tab.windowId, { format: 'png' });
              sendToAgent({ id: msg.id, result: { dataUrl } });
            } catch (e) {
              sendToAgent({ id: msg.id, error: `SCREENSHOT_FAILED: ${e.message}` });
            }
            return;
          }
          if (msg.params?.probeType === 'trigger_html') {
            // Dump inner structure of the prompt-box settings trigger chip —
            // reveals the current mode/model/aspect it displays.
            const tab = (await getAnyFlowTab()) || (await getOrOpenFlowTab());
            if (!tab) {
              sendToAgent({ id: msg.id, error: 'NO_FLOW_TAB' });
              return;
            }
            const results = await chrome.scripting.executeScript({
              target: { tabId: tab.id },
              world: 'MAIN',
              func: () => {
                const t = document.querySelector('.settings-trigger-button');
                const add = document.querySelector('.add-menu-trigger');
                const box = document.querySelector('flow-base-prompt-box');
                return {
                  triggerHtml: t ? t.innerHTML.slice(0, 1500) : null,
                  addHtml: add ? add.innerHTML.slice(0, 800) : null,
                  boxHtml: box ? box.innerHTML.replace(/<svg[\s\S]*?<\/svg>/g, '[svg]').slice(0, 3000) : null,
                };
              },
            });
            sendToAgent({ id: msg.id, result: results?.[0]?.result });
            return;
          }
          if (msg.params?.probeType === 'mode_chips') {
            // Dismiss onboarding, then dump the agent-mode-chip group and its
            // container — the image/video/agent mode selector.
            const tab = (await getAnyFlowTab()) || (await getOrOpenFlowTab());
            if (!tab) {
              sendToAgent({ id: msg.id, error: 'NO_FLOW_TAB' });
              return;
            }
            const results = await chrome.scripting.executeScript({
              target: { tabId: tab.id },
              world: 'MAIN',
              func: async () => {
                const dismiss = Array.from(document.querySelectorAll('button'))
                  .find(b => (b.getAttribute('aria-label') || '').includes('dismiss onboarding') || (b.innerText || '').includes('Got it'));
                if (dismiss) { dismiss.click(); await new Promise(r => setTimeout(r, 500)); }
                const pick = (el) => ({
                  tag: el.tagName.toLowerCase(),
                  text: (el.innerText || '').trim().replace(/\n/g, ' | ').slice(0, 80),
                  aria: el.getAttribute('aria-label'),
                  cls: (typeof el.className === 'string' ? el.className : '').split(/\s+/).filter(Boolean).slice(0, 4).join('.'),
                });
                const chips = Array.from(document.querySelectorAll('[class*="mode-chip"], [class*="agent-mode"], button[class*="chip"]')).map(pick);
                // parents of the chip to find the chip row
                const chip = document.querySelector('.agent-mode-chip');
                const containers = [];
                let n = chip;
                for (let i = 0; n && i < 4; i++, n = n.parentElement) {
                  containers.push({
                    cls: (typeof n.className === 'string' ? n.className : '').split(/\s+/).filter(Boolean).slice(0, 5).join('.'),
                    text: (n.innerText || '').trim().replace(/\n/g, ' | ').slice(0, 200),
                    kids: Array.from(n.children).map(c => `${c.tagName.toLowerCase()}.${(typeof c.className === 'string' ? c.className : '').split(' ')[0]}:${(c.innerText || '').trim().slice(0, 30)}`).slice(0, 10),
                  });
                }
                return { chips, containers };
              },
            });
            sendToAgent({ id: msg.id, result: results?.[0]?.result });
            return;
          }
          if (msg.params?.probeType === 'toggle_agent') {
            // Toggle the "Agent" mode chip off and re-dump the prompt box —
            // hypothesis: non-agent mode exposes the classic image/video
            // model families in the quick-settings panel.
            const tab = (await getAnyFlowTab()) || (await getOrOpenFlowTab());
            if (!tab) {
              sendToAgent({ id: msg.id, error: 'NO_FLOW_TAB' });
              return;
            }
            const results = await chrome.scripting.executeScript({
              target: { tabId: tab.id },
              world: 'MAIN',
              func: async () => {
                const chip = document.querySelector('.agent-mode-chip');
                if (!chip) return { error: 'NO_AGENT_CHIP' };
                const wasChecked = chip.className.includes('checked');
                chip.click();
                await new Promise(r => setTimeout(r, 800));
                const pick = (el) => ({
                  tag: el.tagName.toLowerCase(),
                  text: (el.innerText || '').trim().replace(/\n/g, ' | ').slice(0, 80),
                  aria: el.getAttribute('aria-label'),
                  cls: (typeof el.className === 'string' ? el.className : '').split(/\s+/).filter(Boolean).slice(0, 4).join('.'),
                });
                const chip2 = document.querySelector('.agent-mode-chip');
                const box = document.querySelector('flow-base-prompt-box');
                const boxBtns = box ? Array.from(box.querySelectorAll('button')).map(pick) : [];
                // open quick settings to see if model family changed
                const trigger = document.querySelector('.settings-trigger-button:not([hidden])') || document.querySelector('.settings-trigger-button');
                if (trigger) { trigger.click(); await new Promise(r => setTimeout(r, 800)); }
                const overlay = document.querySelector('.cdk-overlay-container');
                return {
                  wasChecked, nowChecked: chip2 ? chip2.className.includes('checked') : null,
                  boxText: (box?.innerText || '').trim().slice(0, 400),
                  boxBtns, overlayText: (overlay?.innerText || '').trim().slice(0, 800),
                };
              },
            });
            sendToAgent({ id: msg.id, result: results?.[0]?.result });
            return;
          }
          if (msg.params?.probeType === 'debug_state') {
            // Extension-side diagnostics: log ring, last error, DOM video jobs.
            const stored = await chrome.storage.local.get(['debugLog', 'metrics']);
            const sess = await chrome.storage.session.get('domVideoJobs').catch(() => ({}));
            sendToAgent({
              id: msg.id,
              result: {
                lastError: stored?.metrics?.lastError || null,
                jobs: sess?.domVideoJobs || [],
                log: (stored?.debugLog || []).slice(-40),
              },
            });
            return;
          }
          if (msg.params?.probeType === 'page_state') {
            // Post-generation diagnosis: editor contents, media grid, toasts.
            const tab = (await getAnyFlowTab()) || (await getOrOpenFlowTab());
            if (!tab) {
              sendToAgent({ id: msg.id, error: 'NO_FLOW_TAB' });
              return;
            }
            const results = await chrome.scripting.executeScript({
              target: { tabId: tab.id },
              world: 'MAIN',
              func: () => {
                const mediaUrls = new Set();
                for (const el of document.querySelectorAll('video[src], video source[src], img[src], [poster]')) {
                  const v = el.src || el.getAttribute('src') || el.getAttribute('poster') || '';
                  if (v && !v.startsWith('data:') && !v.includes('gstatic')) mediaUrls.add(v);
                }
                const perf = performance.getEntriesByType('resource')
                  .map(e => e.name).filter(u => u.includes('flow-content') || u.includes('googleusercontent')).slice(-15);
                const cards = Array.from(document.querySelectorAll('[class*="card"], [class*="tile"], [class*="media"], flow-media-item, [class*="result"]'))
                  .slice(0, 15).map(el => ({ cls: (typeof el.className === 'string' ? el.className : '').split(/\s+/).filter(Boolean).slice(0, 3).join('.'), text: (el.innerText || '').trim().slice(0, 60) }));
                const editor = document.querySelector('.ProseMirror');
                const genBtn = document.querySelector('.generate-icon-button');
                return {
                  url: location.href,
                  editorText: (editor?.innerText || '').trim().slice(0, 200),
                  genDisabled: genBtn ? genBtn.disabled : null,
                  chipChecked: !!document.querySelector('.agent-mode-chip-checked'),
                  overlayOpen: !!document.querySelector('.cdk-overlay-container .cdk-overlay-pane'),
                  mediaUrls: [...mediaUrls].slice(-20),
                  perf,
                  cards,
                  progressEls: document.querySelectorAll('[class*="progress"], [class*="spinner"], mat-progress-bar, mat-spinner, [role="progressbar"]').length,
                };
              },
            });
            sendToAgent({ id: msg.id, result: results?.[0]?.result });
            return;
          }
          if (msg.params?.probeType === 'harvest_videos') {
            // Hover every grid tile so lazy <video> elements load, then
            // return strict flow-content /video/ URLs (DOM + perf).
            const tab = (await getAnyFlowTab()) || (await getOrOpenFlowTab());
            if (!tab) {
              sendToAgent({ id: msg.id, error: 'NO_FLOW_TAB' });
              return;
            }
            const results = await chrome.scripting.executeScript({
              target: { tabId: tab.id },
              world: 'MAIN',
              func: async () => {
                const sleep = (ms) => new Promise(r => setTimeout(r, ms));
                const tiles = new Set();
                for (const img of document.querySelectorAll('img')) {
                  const s = (img.currentSrc || img.src || '') + ' ' + (img.srcset || '');
                  if (!s.includes('flow-content')) continue;
                  tiles.add(img.closest('[class*="project-tile"]:not([class*="footer"])')
                    || img.closest('[class*="tile"]') || img);
                }
                const list = [...tiles].slice(0, 20);
                for (const t of list) {
                  try {
                    t.scrollIntoView({ block: 'center' });
                    await sleep(400);
                    for (const type of ['pointerover', 'mouseover', 'mouseenter']) {
                      t.dispatchEvent(new MouseEvent(type, { bubbles: type !== 'mouseenter', cancelable: true }));
                    }
                    await sleep(1400);
                  } catch { }
                }
                const vids = new Set();
                for (const v of document.querySelectorAll('video')) {
                  const s = v.currentSrc || v.src || '';
                  if (/flow-content\.google\/video\//.test(s)) vids.add(s);
                }
                for (const e of performance.getEntriesByType('resource')) {
                  if (/flow-content\.google\/video\//.test(e.name)) vids.add(e.name);
                }
                return { tiles: list.length, videoUrls: [...vids] };
              },
            });
            sendToAgent({ id: msg.id, result: results?.[0]?.result });
            return;
          }
          if (msg.params?.probeType === 'open_tiles') {
            // Click each grid tile to open the viewer, capture the real
            // <video> src paired with its thumbnail, then close the viewer.
            const tab = (await getAnyFlowTab()) || (await getOrOpenFlowTab());
            if (!tab) {
              sendToAgent({ id: msg.id, error: 'NO_FLOW_TAB' });
              return;
            }
            const results = await chrome.scripting.executeScript({
              target: { tabId: tab.id },
              world: 'MAIN',
              func: async (rawArgs) => {
                const sleep = (ms) => new Promise(r => setTimeout(r, ms));
                const args = rawArgs && typeof rawArgs === 'object' ? rawArgs : {};
                const start = Math.max(0, args.start || 0);
                const count = 1;
                const seen = new Set(args.known || []);
                const tiles = [];
                const pushTile = (el) => {
                  const t = el.closest ? (el.closest('[class*="tile"]') || el) : el;
                  if (t && !tiles.includes(t)) tiles.push(t);
                };
                for (const img of document.querySelectorAll('img')) {
                  const s = (img.currentSrc || img.src || '') + ' ' + (img.srcset || '');
                  if (s.includes('flow-content')) pushTile(img);
                }
                for (const el of document.querySelectorAll('[class*="project-tile"], [class*="media-item"], flow-media-item')) pushTile(el);
                // Clicking a tile navigates to the /edit/<mediaId> route which
                // fetches the real video file; harvest it from the full perf
                // buffer, then go back to the grid for the next tile.
                const uuidOf = (u) => (u.match(/flow-content\.google\/video\/([a-f0-9-]+)/) || [])[1] || u;
                for (const k of (args.known || [])) seen.add(k);
                const pairs = [];
                // Each grid thumbnail img IS one video tile (rows share one
                // .tile-row ancestor, so group by the img element itself).
                const queryTiles = () => {
                  const out = [];
                  for (const img of document.querySelectorAll('img')) {
                    const s = (img.currentSrc || img.src || '') + ' ' + (img.srcset || '');
                    if (s.includes('flow-content')) out.push(img);
                  }
                  return out;
                };
                const ensureGrid = async () => {
                  if (/\/edit\//.test(location.href)) history.back();
                  for (let i = 0; i < 20 && (/\/edit\//.test(location.href) || !queryTiles().length); i++) await sleep(500);
                  await sleep(1500);
                };
                await ensureGrid();
                const perfNames = () => performance.getEntriesByType('resource').map(e => e.name);
                for (let n = 0; n < count; n++) {
                  const idx = start + n;
                  try {
                    const fresh = queryTiles();
                    const t = fresh[idx];
                    if (!t) { pairs.push({ skipped: idx }); continue; }
                    const img = (t.tagName === 'IMG') ? t : t.querySelector('img');
                    const thumb = img ? (img.currentSrc || img.src || '') : null;
                    const baseline = new Set(perfNames());
                    t.scrollIntoView({ block: 'center' });
                    await sleep(400);
                    (img || t).click();
                    for (let i = 0; i < 10 && !/\/edit\//.test(location.href); i++) await sleep(500);
                    // Edit view lazy-loads the file: hit play on the preview.
                    try {
                      const playBtn = document.querySelector('[aria-label*="lay" i], button[class*="lay" i], [class*="play-button" i]');
                      if (playBtn) playBtn.click();
                      await sleep(800);
                      const preview = document.querySelector('video, canvas, [class*="preview" i] img, [class*="viewer" i] img')
                        || document.querySelector('img');
                      if (preview) {
                        const r = preview.getBoundingClientRect();
                        for (const type of ['pointerdown', 'mousedown', 'mouseup', 'click']) {
                          preview.dispatchEvent(new MouseEvent(type, {
                            bubbles: true, cancelable: true,
                            clientX: r.x + r.width / 2, clientY: r.y + r.height / 2,
                          }));
                        }
                      }
                      document.body.dispatchEvent(new KeyboardEvent('keydown', { key: ' ', code: 'Space', bubbles: true }));
                    } catch { }
                    let freshVids = [];
                    let freshAll = [];
                    for (let i = 0; i < 10; i++) {
                      await sleep(1000);
                      freshAll = perfNames().filter(u => !baseline.has(u));
                      freshVids = freshAll.filter(u => /flow-content\.google\/video\//.test(u));
                      if (freshVids.length) break;
                    }
                    const mediaId = (location.href.match(/\/edit\/([a-f0-9-]+)/) || [])[1] || null;
                    for (const v of freshVids) { seen.add(uuidOf(v)); pairs.push({ thumb, mediaId, video: v }); }
                    if (!freshVids.length) pairs.push({ thumb, mediaId, video: null, netNew: freshAll.slice(0, 40) });
                    if (/\/edit\//.test(location.href)) history.back();
                    for (let i = 0; i < 8 && /\/edit\//.test(location.href); i++) await sleep(500);
                    await sleep(1500);
                  } catch { try { if (/\/edit\//.test(location.href)) history.back(); } catch { } }
                }
                if (/\/edit\//.test(location.href)) history.back();
                return { tiles: queryTiles().length, start, pairs };
              },
              args: [msg.params?.args || {}],
            });
            sendToAgent({ id: msg.id, result: results?.[0]?.result });
            return;
          }
          if (msg.params?.probeType === 'tile_debug') {
            const tab = (await getAnyFlowTab()) || (await getOrOpenFlowTab());
            if (!tab) {
              sendToAgent({ id: msg.id, error: 'NO_FLOW_TAB' });
              return;
            }
            const results = await chrome.scripting.executeScript({
              target: { tabId: tab.id },
              world: 'MAIN',
              func: async () => {
                const sleep = (ms) => new Promise(r => setTimeout(r, ms));
                const before = location.href;
                const firstImg = [...document.querySelectorAll('img')].find(i => ((i.currentSrc || i.src || '') + ' ' + (i.srcset || '')).includes('flow-content'));
                if (!firstImg) return { error: 'NO_THUMB' };
                const tile = firstImg.closest('[class*="tile"]') || firstImg;
                tile.scrollIntoView({ block: 'center' });
                await sleep(500);
                (firstImg).click();
                await sleep(3000);
                const vids = [...document.querySelectorAll('video')].map(v => ({
                  src: (v.currentSrc || v.src || '').slice(0, 120),
                  ready: v.readyState, w: v.videoWidth,
                }));
                const perfV = performance.getEntriesByType('resource').map(e => e.name).filter(u => /flow-content\.google\/video\//.test(u));
                const ov = document.querySelector('.cdk-overlay-container .cdk-overlay-pane');
                return {
                  hrefBefore: before.slice(-60), hrefAfter: location.href.slice(-80),
                  tileCls: tile.className && tile.className.baseVal !== undefined ? 'SVG' : String(tile.className).split(/\s+/).slice(0, 4).join('.'),
                  videos: vids, perfVideos: perfV.length,
                  overlay: ov ? ov.innerHTML.slice(0, 200) : null,
                  bodyTail: document.body.innerHTML.slice(-300),
                };
              },
            });
            sendToAgent({ id: msg.id, result: results?.[0]?.result });
            return;
          }
          if (msg.params?.probeType === 'grid_debug') {
            const tab = (await getAnyFlowTab()) || (await getOrOpenFlowTab());
            if (!tab) {
              sendToAgent({ id: msg.id, error: 'NO_FLOW_TAB' });
              return;
            }
            const results = await chrome.scripting.executeScript({
              target: { tabId: tab.id },
              world: 'MAIN',
              func: () => {
                const imgs = [...document.querySelectorAll('img')];
                const withSrc = imgs.filter(i => i.getAttribute('src'));
                const curFlow = imgs.filter(i => (i.currentSrc || '').includes('flow-content'));
                const attrFlow = imgs.filter(i => (i.getAttribute('src') || '').includes('flow-content'));
                const setFlow = imgs.filter(i => (i.srcset || '').includes('flow-content'));
                const sample = imgs.slice(0, 4).map(i => ({
                  src: (i.getAttribute('src') || '').slice(0, 80),
                  cur: (i.currentSrc || '').slice(0, 80),
                  set: (i.srcset || '').slice(0, 80),
                }));
                const groups = {};
                for (const i of imgs.filter(i => (i.currentSrc || '').includes('flow-content'))) {
                  const a = i.closest('[class*="project-tile"]');
                  const b = i.closest('[class*="tile"]');
                  const key = (a ? 'P:' + String(a.className).split(/\s+/).slice(0,3).join('.') : 'noP')
                    + ' | T:' + (b ? String(b.className).split(/\s+/).slice(0,3).join('.') : 'noT');
                  groups[key] = (groups[key] || 0) + 1;
                }
                const scroller = document.querySelector('.tiles-container, cdk-virtual-scroll-viewport');
                const perfVid = [...new Set(performance.getEntriesByType('resource')
                  .map(e => e.name).filter(u => /flow-content\.google\/video\//.test(u)))];
                return {
                  perfVidCount: perfVid.length,
                  perfVid: perfVid.slice(0, 20),
                  href: location.href.slice(-40),
                  imgs: imgs.length, withSrc: withSrc.length,
                  curFlow: curFlow.length, attrFlow: attrFlow.length, setFlow: setFlow.length,
                  videos: document.querySelectorAll('video').length,
                  posters: document.querySelectorAll('[poster]').length,
                  scroller: scroller ? { h: scroller.scrollHeight, top: scroller.scrollTop } : null,
                  groups, sample,
                };
              },
            });
            sendToAgent({ id: msg.id, result: results?.[0]?.result });
            return;
          }
          if (msg.params?.probeType === 'media_redirect') {
            // Resolve flow-content /video/ URLs page-side (cookies included)
            // via the media getMediaUrlRedirect TRPC endpoint.
            const tab = (await getAnyFlowTab()) || (await getOrOpenFlowTab());
            if (!tab) {
              sendToAgent({ id: msg.id, error: 'NO_FLOW_TAB' });
              return;
            }
            const results = await chrome.scripting.executeScript({
              target: { tabId: tab.id },
              world: 'MAIN',
              func: async (rawArgs) => {
                const args = rawArgs && typeof rawArgs === 'object' ? rawArgs : {};
                const names = args.names || [];
                const thumbs = [...document.querySelectorAll('img')]
                  .map(i => i.currentSrc || i.src || '')
                  .filter(s => s.includes('flow-content.google/image/'));
                const out = [];
                for (const name of names.slice(0, 16)) {
                  const tries = [
                    'https://labs.google/fx/api/trpc/media.getMediaUrlRedirect?name=' + encodeURIComponent(name),
                    'https://labs.google/fx/api/trpc/media.getMediaUrlRedirect?batch=1&input=' + encodeURIComponent(JSON.stringify({ 0: { json: { name } } })),
                  ];
                  for (const url of tries) {
                    try {
                      const resp = await fetch(url, { credentials: 'include', redirect: 'follow' });
                      const text = await resp.text().then(t => t.slice(0, 300)).catch(() => '');
                      out.push({ name, tryUrl: url.slice(0, 80), status: resp.status, finalUrl: resp.url.slice(0, 140), body: text });
                      const m = text.match(/https:[^"\\ ]*flow-content\.google\/video\/[^"\\ ]*/);
                      if (m) { out.push({ name, video: m[0].slice(0, 200) }); break; }
                      if (/flow-content\.google\/video\//.test(resp.url)) break;
                    } catch (e) { out.push({ name, tryUrl: url.slice(0, 80), error: String(e).slice(0, 120) }); }
                  }
                }
                return { thumbs: thumbs.length, out };
              },
              args: [msg.params?.args || {}],
            });
            sendToAgent({ id: msg.id, result: results?.[0]?.result });
            return;
          }
          if (msg.params?.probeType === 'api_fetch') {
            // Background-side fetch (extension host permissions + cookies):
            // resolve signed media URLs without touching page CORS.
            const a = msg.params?.args || {};
            const urls = Array.isArray(a.urls) ? a.urls.slice(0, 20) : [];
            const out = [];
            const authHeader = await getAuthHeader();
            for (const url of urls) {
              try {
                const resp = await fetch(url, {
                  credentials: 'include', redirect: 'follow',
                  headers: {
                    ...(authHeader ? { authorization: authHeader } : {}),
                    'x-origin': 'https://flow.google.com',
                    'x-goog-authuser': '0',
                  },
                });
                const text = await resp.text().then(t => t.slice(0, 400)).catch(() => '');
                out.push({ url: url.slice(0, 100), status: resp.status, finalUrl: resp.url.slice(0, 220), body: text });
              } catch (e) { out.push({ url: url.slice(0, 100), error: String(e && e.message || e).slice(0, 150) }); }
            }
            sendToAgent({ id: msg.id, result: { out } });
            return;
          }
          if (msg.params?.probeType === 'edit_debug') {
            const tab = (await getAnyFlowTab()) || (await getOrOpenFlowTab());
            if (!tab) {
              sendToAgent({ id: msg.id, error: 'NO_FLOW_TAB' });
              return;
            }
            const results = await chrome.scripting.executeScript({
              target: { tabId: tab.id },
              world: 'MAIN',
              func: async (rawArgs) => {
                const sleep = (ms) => new Promise(r => setTimeout(r, ms));
                const args = rawArgs && typeof rawArgs === 'object' ? rawArgs : {};
                if (/\/edit\//.test(location.href)) history.back();
                for (let i = 0; i < 12 && (/\/edit\//.test(location.href)); i++) await sleep(500);
                await sleep(1500);
                const imgs = [...document.querySelectorAll('img')]
                  .filter(i => ((i.currentSrc || i.src || '') + ' ' + (i.srcset || '')).includes('flow-content'));
                const t = imgs[args.index || 0];
                if (t) {
                  t.scrollIntoView({ block: 'center' });
                  await sleep(400);
                  t.click();
                  for (let i = 0; i < 10 && !/\/edit\//.test(location.href); i++) await sleep(500);
                  await sleep(3000);
                }
                const btns = [...document.querySelectorAll('button, [role="menuitem"], a')]
                  .map(b => ((b.getAttribute('aria-label') || '') + '|' + (b.innerText || '').trim()).slice(0, 60))
                  .filter(s => s.replace(/\|/g, '').trim())
                  .slice(0, 50);
                return {
                  href: location.href.slice(-50),
                  videos: document.querySelectorAll('video').length,
                  canvases: document.querySelectorAll('canvas').length,
                  btns,
                };
              },
              args: [msg.params?.args || {}],
            });
            sendToAgent({ id: msg.id, result: results?.[0]?.result });
            return;
          }
          if (msg.params?.probeType === 'download_next') {
            // Walk the edit viewer (grid tile click or Next-media arrow) and
            // press "Download media"; the file lands in ~/Downloads.
            const tab = (await getAnyFlowTab()) || (await getOrOpenFlowTab());
            if (!tab) {
              sendToAgent({ id: msg.id, error: 'NO_FLOW_TAB' });
              return;
            }
            const results = await chrome.scripting.executeScript({
              target: { tabId: tab.id },
              world: 'MAIN',
              func: async (rawArgs) => {
                const sleep = (ms) => new Promise(r => setTimeout(r, ms));
                const args = rawArgs && typeof rawArgs === 'object' ? rawArgs : {};
                const mediaIdNow = () => (location.href.match(/\/edit\/([a-f0-9-]+)/) || [])[1] || null;
                if (!/\/edit\//.test(location.href)) {
                  const imgs = [...document.querySelectorAll('img')]
                    .filter(i => ((i.currentSrc || i.src || '') + ' ' + (i.srcset || '')).includes('flow-content'));
                  const t = imgs[args.first_index || 0];
                  if (!t) return { error: 'NO_TILE' };
                  t.scrollIntoView({ block: 'center' });
                  await sleep(400);
                  t.click();
                  for (let i = 0; i < 10 && !/\/edit\//.test(location.href); i++) await sleep(500);
                } else if (args.next) {
                  const before = mediaIdNow();
                  const nextBtn = [...document.querySelectorAll('button')]
                    .find(b => (b.getAttribute('aria-label') || '').toLowerCase().includes('next media'));
                  if (!nextBtn) return { error: 'NO_NEXT_BTN', mediaId: before };
                  nextBtn.click();
                  for (let i = 0; i < 10 && mediaIdNow() === before; i++) await sleep(500);
                }
                await sleep(2000);
                const dlBtn = [...document.querySelectorAll('button')]
                  .find(b => (b.getAttribute('aria-label') || '').toLowerCase().includes('download'));
                if (!dlBtn) return { error: 'NO_DL_BTN', mediaId: mediaIdNow() };
                dlBtn.click();
                await sleep(12000);
                return { mediaId: mediaIdNow(), href: location.href.slice(-50), downloaded: true };
              },
              args: [msg.params?.args || {}],
            });
            sendToAgent({ id: msg.id, result: results?.[0]?.result });
            return;
          }
          if (msg.params?.probeType === 'dl_debug') {
            const tab = (await getAnyFlowTab()) || (await getOrOpenFlowTab());
            if (!tab) {
              sendToAgent({ id: msg.id, error: 'NO_FLOW_TAB' });
              return;
            }
            const results = await chrome.scripting.executeScript({
              target: { tabId: tab.id },
              world: 'MAIN',
              func: async () => {
                const sleep = (ms) => new Promise(r => setTimeout(r, ms));
                const dlBtn = [...document.querySelectorAll('button')]
                  .find(b => (b.getAttribute('aria-label') || '').toLowerCase().includes('download'));
                if (!dlBtn) return { error: 'NO_DL_BTN', href: location.href.slice(-50) };
                dlBtn.click();
                await sleep(3000);
                const dump = (sel) => [...document.querySelectorAll(sel)].map(e =>
                  (e.outerHTML || '').slice(0, 400)).slice(0, 6);
                return {
                  href: location.href.slice(-50),
                  menus: dump('[role="menu"], [role="listbox"], .cdk-overlay-pane mat-menu, mat-menu'),
                  dialogs: dump('[role="dialog"], mat-dialog-container'),
                  menuitems: [...document.querySelectorAll('[role="menuitem"], mat-menu-item, [role="menuitemradio"]')]
                    .map(b => ((b.getAttribute('aria-label') || '') + '|' + (b.innerText || '').trim()).slice(0, 80)).slice(0, 12),
                  newBtns: [...document.querySelectorAll('button')]
                    .map(b => ((b.getAttribute('aria-label') || '') + '|' + (b.innerText || '').trim()).slice(0, 60))
                    .filter(s => /gif|mp4|download|1080|720|quality|size|format/i.test(s)).slice(0, 12),
                };
              },
            });
            sendToAgent({ id: msg.id, result: results?.[0]?.result });
            return;
          }
          if (msg.params?.probeType === 'test_submit') {
            // Diagnose submit mechanics: does the prompt reach PM state and
            // does a full pointer-event sequence on the generate button fire?
            const tab = (await getAnyFlowTab()) || (await getOrOpenFlowTab());
            if (!tab) {
              sendToAgent({ id: msg.id, error: 'NO_FLOW_TAB' });
              return;
            }
            const results = await chrome.scripting.executeScript({
              target: { tabId: tab.id },
              world: 'MAIN',
              func: async (promptText) => {
                const sleep = (ms) => new Promise(r => setTimeout(r, ms));
                const editor = Array.from(document.querySelectorAll('.ProseMirror'))
                  .find(e => e.offsetParent !== null) || document.querySelector('.ProseMirror');
                if (!editor) return { error: 'NO_EDITOR' };
                const box = editor.closest('flow-base-prompt-box') || document;
                const genBtn = box.querySelector('.generate-icon-button');

                // A) does execCommand update ProseMirror state? check PM doc via
                // the view if reachable, else proxy via DOM text + beforeinput.
                editor.focus();
                document.execCommand('selectAll', false, null);
                const inserted = document.execCommand('insertText', false, promptText);
                await sleep(400);
                const domText = editor.innerText.trim();
                // ProseMirror stores its EditorView on the DOM node in some
                // builds; also check for pmViewDesc/editor props.
                const pmKeys = Object.keys(editor).filter(k => /pm|view|editor/i.test(k));
                const parentKeys = editor.parentElement ? Object.keys(editor.parentElement).filter(k => /pm|view|editor/i.test(k)) : [];

                // B) full pointer sequence on the real button
                const before = document.querySelector('.tiles-container')?.className || '';
                const ev = (type, opts = {}) => genBtn.dispatchEvent(new (type.startsWith('pointer') || type.startsWith('mouse') ? PointerEvent : Event)(type, { bubbles: true, cancelable: true, ...opts }));
                if (genBtn) {
                  ['pointerover', 'pointerdown', 'mousedown', 'pointerup', 'mouseup', 'click'].forEach(t => ev(t));
                }
                await sleep(2500);
                return {
                  inserted, domText: domText.slice(0, 80), pmKeys, parentKeys,
                  genDisabled: genBtn ? genBtn.disabled : null,
                  tilesAfter: document.querySelector('.tiles-container')?.className || '',
                  tilesBefore: before,
                  editorAfter: (editor.innerText || '').trim().slice(0, 80),
                  progressNow: document.querySelectorAll('[class*="progress"], mat-progress-bar, mat-spinner, [role="progressbar"]').length,
                };
              },
              args: ['probe banana test'],
            });
            sendToAgent({ id: msg.id, result: results?.[0]?.result });
            return;
          }
          if (msg.params?.probeType === 'pm_state') {
            // Inspect the ProseMirror view state & try an Enter-key submit.
            const tab = (await getAnyFlowTab()) || (await getOrOpenFlowTab());
            if (!tab) {
              sendToAgent({ id: msg.id, error: 'NO_FLOW_TAB' });
              return;
            }
            const results = await chrome.scripting.executeScript({
              target: { tabId: tab.id },
              world: 'MAIN',
              func: async () => {
                const sleep = (ms) => new Promise(r => setTimeout(r, ms));
                const editor = Array.from(document.querySelectorAll('.ProseMirror'))
                  .find(e => e.offsetParent !== null) || document.querySelector('.ProseMirror');
                if (!editor) return { error: 'NO_EDITOR' };
                const out = { pmDocText: null, enterSubmitted: null, tilesAfter: null, editorAfter: null };
                // PM stores its view descriptor on the DOM node; the EditorView
                // is reachable through it on most builds.
                try {
                  const vd = editor.pmViewDesc;
                  const view = vd && (vd.view || vd.editorView || (vd.node && vd.node.view));
                  if (view && view.state) {
                    out.pmDocText = view.state.doc.textContent.slice(0, 100);
                    // try a real PM transaction to (re)insert text deterministically
                    const tr = view.state.tr.insertText('pm transaction probe');
                    view.dispatch(tr);
                    out.afterTr = view.state.doc.textContent.slice(0, 100);
                  } else {
                    out.vdKeys = vd ? Object.keys(vd) : null;
                  }
                } catch (e) { out.pmErr = String(e.message || e); }
                // Enter-key submit attempt (many Flow builds submit on Enter)
                const evOpts = { key: 'Enter', code: 'Enter', keyCode: 13, which: 13, bubbles: true, cancelable: true };
                editor.dispatchEvent(new KeyboardEvent('keydown', evOpts));
                editor.dispatchEvent(new KeyboardEvent('keypress', evOpts));
                editor.dispatchEvent(new KeyboardEvent('keyup', evOpts));
                await sleep(2500);
                out.editorAfter = (editor.innerText || '').trim().slice(0, 100);
                out.tilesAfter = document.querySelector('.tiles-container')?.className || '';
                out.progressNow = document.querySelectorAll('[class*="progress"], mat-spinner, [role="progressbar"]').length;
                return out;
              },
            });
            sendToAgent({ id: msg.id, result: results?.[0]?.result });
            return;
          }
          if (msg.params?.probeType === 'ng_inspect') {
            // Reach the Angular component instance behind the prompt box via
            // __ngContext__ — lets us call submit() directly, bypassing the
            // untrusted-click problem entirely.
            const tab = (await getAnyFlowTab()) || (await getOrOpenFlowTab());
            if (!tab) {
              sendToAgent({ id: msg.id, error: 'NO_FLOW_TAB' });
              return;
            }
            const results = await chrome.scripting.executeScript({
              target: { tabId: tab.id },
              world: 'MAIN',
              func: () => {
                const editor = Array.from(document.querySelectorAll('.ProseMirror'))
                  .find(e => e.offsetParent !== null) || document.querySelector('.ProseMirror');
                if (!editor) return { error: 'NO_EDITOR' };
                const box = editor.closest('flow-base-prompt-box');
                const genBtn = (box || document).querySelector('.generate-icon-button');
                const probe = (el, label) => {
                  if (!el) return { label, missing: true };
                  const ctx = el.__ngContext__;
                  const info = { label, hasCtx: !!ctx };
                  if (ctx) {
                    // LView: index 0 = header, component instance typically at
                    // one of the early slots — scan for objects with methods.
                    info.len = ctx.length;
                    const found = [];
                    for (let i = 0; i < Math.min(ctx.length, 30); i++) {
                      const v = ctx[i];
                      if (v && typeof v === 'object' && !Array.isArray(v)) {
                        const meths = Object.getOwnPropertyNames(Object.getPrototypeOf(v) || {})
                          .filter(k => typeof v[k] === 'function' && k !== 'constructor')
                          .filter(k => /submit|gener|send|click|create|confirm/i.test(k));
                        if (meths.length) found.push({ i, ctor: v.constructor?.name, meths });
                      }
                    }
                    info.components = found.slice(0, 8);
                  }
                  return info;
                };
                // Deep scan: every object in every LView slot chain, all methods
                const scanAll = (el, label) => {
                  const ctx = el && el.__ngContext__;
                  if (!ctx) return { label, hasCtx: false };
                  const comps = [];
                  const seen = new Set();
                  const walk = (view, depth) => {
                    if (!view || depth > 3 || seen.has(view)) return;
                    seen.add(view);
                    for (let i = 0; i < view.length; i++) {
                      const v = view[i];
                      if (v && typeof v === 'object' && !Array.isArray(v) && !(v instanceof Node) && !(v instanceof HTMLElement)) {
                        const proto = Object.getPrototypeOf(v);
                        const ctor = v.constructor?.name || '';
                        if (proto && proto !== Object.prototype && ctor && ctor !== 'Object') {
                          const meths = Object.getOwnPropertyNames(proto)
                            .filter(k => typeof v[k] === 'function' && k !== 'constructor');
                          if (meths.length) comps.push({ slot: i, depth, ctor, meths: meths.slice(0, 40) });
                        }
                      }
                    }
                  };
                  walk(ctx, 0);
                  return { label, hasCtx: true, comps: comps.slice(0, 15) };
                };
                return {
                  btn: scanAll(genBtn, 'genBtn'),
                  box: scanAll(box, 'promptBox'),
                  ngGlobal: typeof window.ng !== 'undefined',
                };
              },
            });
            sendToAgent({ id: msg.id, result: results?.[0]?.result });
            return;
          }
          if (msg.params?.probeType === 'click_trace') {
            // Click generate (scoped to the visible prompt box) and record any
            // network requests fired afterwards — tells us whether the click
            // reached app logic and where the request goes.
            const tab = (await getAnyFlowTab()) || (await getOrOpenFlowTab());
            if (!tab) {
              sendToAgent({ id: msg.id, error: 'NO_FLOW_TAB' });
              return;
            }
            const results = await chrome.scripting.executeScript({
              target: { tabId: tab.id },
              world: 'MAIN',
              func: async () => {
                const sleep = (ms) => new Promise(r => setTimeout(r, ms));
                const editor = Array.from(document.querySelectorAll('.ProseMirror'))
                  .find(e => e.offsetParent !== null) || document.querySelector('.ProseMirror');
                if (!editor) return { error: 'NO_EDITOR' };
                const box = editor.closest('flow-base-prompt-box') || document;
                const genBtn = box.querySelector('.generate-icon-button');
                if (!genBtn) return { error: 'NO_GEN_BUTTON' };
                const mark = performance.now();
                genBtn.click();
                await sleep(4000);
                const reqs = performance.getEntriesByType('resource')
                  .filter(e => e.startTime >= mark && e.entryType === 'resource')
                  .map(e => ({ t: Math.round(e.startTime), u: e.name.slice(0, 160) }))
                  .filter(e => !/gstatic|googleusercontent|\.png|\.css|\.js(\?|$)|fonts/.test(e.u));
                return {
                  editorText: (editor.innerText || '').trim().slice(0, 80),
                  genDisabled: genBtn.disabled,
                  requests: reqs,
                  tiles: document.querySelector('.tiles-container')?.className || '',
                };
              },
            });
            sendToAgent({ id: msg.id, result: results?.[0]?.result });
            return;
          }
          if (msg.params?.probeType === 'list_js') {
            // List JS bundles the page loaded — for locating the compiled
            // component code when auditing handlers.
            const tab = (await getAnyFlowTab()) || (await getOrOpenFlowTab());
            if (!tab) {
              sendToAgent({ id: msg.id, error: 'NO_FLOW_TAB' });
              return;
            }
            const results = await chrome.scripting.executeScript({
              target: { tabId: tab.id },
              world: 'MAIN',
              func: () => ({
                scripts: Array.from(document.querySelectorAll('script[src]')).map(s => s.src),
                resJs: performance.getEntriesByType('resource').map(e => e.name).filter(u => /\.(m?js)($|\?)/.test(u)).slice(-40),
              }),
            });
            sendToAgent({ id: msg.id, result: results?.[0]?.result });
            return;
          }
          if (msg.params?.probeType === 'rpc_log') {
            // Read the batchexecute recorder injected.js keeps in the page.
            const tab = (await getAnyFlowTab()) || (await getOrOpenFlowTab());
            if (!tab) {
              sendToAgent({ id: msg.id, error: 'NO_FLOW_TAB' });
              return;
            }
            const results = await chrome.scripting.executeScript({
              target: { tabId: tab.id },
              world: 'MAIN',
              func: () => ({
                injected: !!window.__FLOW_AGENT_MAIN_INJECTED__,
                hasLog: '__flowRpcLog' in window,
                rpcLog: window.__flowRpcLog || [],
              }),
            });
            sendToAgent({ id: msg.id, result: results?.[0]?.result });
            return;
          }
          if (msg.params?.probeType === 'list_js') {
            const tab = (await getAnyFlowTab()) || (await getOrOpenFlowTab());
            if (!tab) {
              sendToAgent({ id: msg.id, error: 'NO_FLOW_TAB' });
              return;
            }
            const results = await chrome.scripting.executeScript({
              target: { tabId: tab.id },
              world: 'MAIN',
              func: async () => {
                const btn = Array.from(document.querySelectorAll('button')).find(b => b.innerText?.includes('crop_') || b.innerText?.includes('Banana') || b.innerText?.includes('Video') || b.innerText?.includes('Image'));
                if (!btn) return { error: 'NO_BUTTON' };
                btn.click();
                await new Promise(r => setTimeout(r, 600));
                const items = Array.from(document.querySelectorAll('[role="menuitem"], [role="option"], mat-option, .cdk-overlay-container *'))
                  .map(el => el.innerText?.trim())
                  .filter(Boolean)
                  .filter((v, i, a) => a.indexOf(v) === i);
                // click again or press Escape to close menu
                document.body.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', code: 'Escape', bubbles: true }));
                return { btnText: btn.innerText?.trim().replace(/\n/g, ' '), items };
              }
            });
            sendToAgent({ id: msg.id, result: results?.[0]?.result });
            return;
          }
          if (msg.params?.probeType === 'inspect_recent') {
            const tab = (await getAnyFlowTab()) || (await getOrOpenFlowTab());
            if (!tab) {
              sendToAgent({ id: msg.id, error: 'NO_FLOW_TAB' });
              return;
            }
            const results = await chrome.scripting.executeScript({
              target: { tabId: tab.id },
              world: 'MAIN',
              func: () => {
                const resources = performance.getEntriesByType('resource')
                  .map(r => r.name)
                  .filter(n => n.includes('batchexecute') || n.includes('asb') || n.includes('flow') || n.includes('sandbox'));

                const allImgs = Array.from(document.querySelectorAll('img')).map(i => ({ src: i.src.slice(0, 100), width: i.width, height: i.height }));
                const bgImgs = Array.from(document.querySelectorAll('*'))
                  .map(el => window.getComputedStyle(el).backgroundImage)
                  .filter(bg => bg && bg !== 'none' && !bg.includes('gradient'))
                  .slice(0, 10);

                const editor = document.querySelector('.ProseMirror, [contenteditable="true"]');
                const genBtn = Array.from(document.querySelectorAll('button')).find(b => b.innerText?.includes('arrow_forward') || b.getAttribute('aria-label')?.includes('Generate'));

                return {
                  url: window.location.href,
                  editorText: editor?.innerText?.trim(),
                  genBtnDisabled: genBtn?.disabled,
                  recentResources: resources.slice(-20),
                  allImgs,
                  bgImgs
                };
              }
            });
            sendToAgent({ id: msg.id, result: results?.[0]?.result });
            return;
          }
          if (msg.params?.probeType === 'generate_image') {
            let probeTab = (await getAnyFlowTab()) || (await getOrOpenFlowTab());
            probeTab = await ensureProjectPage(probeTab);
            if (!probeTab) {
              sendToAgent({ id: msg.id, error: 'NO_FLOW_TAB' });
              return;
            }
            const results = await chrome.scripting.executeScript({
              target: { tabId: probeTab.id },
              world: 'MAIN',
              func: async (promptText) => {
                try {
                  const findEditor = () =>
                    document.querySelector('.ProseMirror, [contenteditable="true"], [role="textbox"]');
                  let editor = findEditor();
                  for (let i = 0; !editor && i < 40; i++) {
                    await new Promise(r => setTimeout(r, 500));
                    editor = findEditor();
                  }
                  if (!editor) return { error: 'NO_EDITOR' };
                  
                  // Switch to Image mode
                  const modeButton = Array.from(document.querySelectorAll('button')).find(b => b.innerText?.includes('Video') || b.innerText?.includes('Image'));
                  if (modeButton) {
                    modeButton.click();
                    await new Promise(r => setTimeout(r, 400));
                    const allClickables = Array.from(document.querySelectorAll('button, [role="menuitem"], [role="option"], div, span'));
                    const imgOption = allClickables.find(el => {
                      const t = el.innerText?.trim();
                      return t === 'Image' || t === 'image\nImage';
                    });
                    if (imgOption) {
                      imgOption.click();
                      await new Promise(r => setTimeout(r, 400));
                    }
                  }

                  // Focus and type prompt into editor
                  editor.focus();
                  document.execCommand('selectAll', false, null);
                  document.execCommand('insertText', false, promptText);
                  editor.dispatchEvent(new Event('input', { bubbles: true }));
                  editor.dispatchEvent(new Event('change', { bubbles: true }));
                  await new Promise(r => setTimeout(r, 400));

                  const generateButton = Array.from(document.querySelectorAll('button')).find(b => b.innerText?.includes('arrow_forward') || b.getAttribute('aria-label')?.includes('Generate'));
                  if (!generateButton || generateButton.disabled) {
                    return { error: 'BUTTON_DISABLED_OR_MISSING' };
                  }

                  // Count existing images
                  const beforeImgs = Array.from(document.querySelectorAll('img')).map(i => i.src);

                  // Click generate!
                  generateButton.click();
                  const startTime = Date.now();
                  
                  // Poll for new image
                  let newImageSrc = null;
                  for (let i = 0; i < 45; i++) {
                    await new Promise(r => setTimeout(r, 1000));
                    const imgs = Array.from(document.querySelectorAll('img')).map(img => img.src);
                    const asbImg = imgs.find(src => (src.includes('/asb/') || src.includes('flow.google.com')) && !src.includes('avatar') && !beforeImgs.includes(src));
                    if (asbImg) {
                      newImageSrc = asbImg;
                      break;
                    }
                  }

                  // If found, fetch image blob and convert to data url
                  let dataUrl = null;
                  if (newImageSrc) {
                    try {
                      const r = await fetch(newImageSrc, { credentials: 'include' });
                      const blob = await r.blob();
                      dataUrl = await new Promise((resolve) => {
                        const reader = new FileReader();
                        reader.onloadend = () => resolve(reader.result);
                        reader.readAsDataURL(blob);
                      });
                    } catch (fetchErr) {
                      dataUrl = null;
                    }
                  }

                  return {
                    ok: !!newImageSrc,
                    elapsedMs: Date.now() - startTime,
                    imageUrl: newImageSrc,
                    dataUrl
                  };
                } catch (e) {
                  return { ok: false, error: e.message };
                }
              },
              args: [msg.params?.prompt || 'a cute glowing origami fox sitting on an open book, soft warm studio lighting']
            });
            sendToAgent({ id: msg.id, result: results?.[0]?.result });
            return;
          }
          const tab = (await getAnyFlowTab()) || (await getOrOpenFlowTab());
          if (!tab) {
            sendToAgent({ id: msg.id, error: 'NO_FLOW_TAB' });
            return;
          }
          const sapisid = await getSapisidCookie();
          const authHdr = await getAuthHeader();
          const results = await chrome.scripting.executeScript({
            target: { tabId: tab.id },
            world: 'MAIN',
            func: async (sapisidVal) => {
              const resList = performance.getEntriesByType('resource')
                .map(r => r.name)
                .filter(n => n.includes('google') || n.includes('sandbox') || n.includes('trpc') || n.includes('api'));
              
              const ls = {};
              for (let i = 0; i < localStorage.length; i++) {
                const k = localStorage.key(i);
                ls[k] = localStorage.getItem(k)?.slice(0, 100);
              }

              const tests = {};
              
              // 1. Search window for ya29
              let ya29Found = [];
              try {
                if (window.WIZ_global_data) {
                  for (const [k, v] of Object.entries(window.WIZ_global_data)) {
                    if (typeof v === 'string' && (v.includes('ya29.') || k.toLowerCase().includes('token') || k.toLowerCase().includes('auth'))) {
                      ya29Found.push({ wiz: k, val: v.slice(0, 50) });
                    }
                  }
                }
              } catch (e) { ya29Found.push({ wizError: e.message }); }

              // 2. Search scripts and html for ya29
              try {
                const html = document.documentElement.innerHTML;
                const matches = html.match(/ya29\.[a-zA-Z0-9_\-]+/g);
                if (matches) {
                  ya29Found.push({ htmlMatches: matches.map(m => m.slice(0, 30)) });
                }
              } catch (e) { ya29Found.push({ htmlError: e.message }); }

              // 3. Search localStorage and sessionStorage for ya29
              try {
                for (let i = 0; i < sessionStorage.length; i++) {
                  const k = sessionStorage.key(i);
                  const v = sessionStorage.getItem(k);
                  if (v && v.includes('ya29.')) ya29Found.push({ session: k, val: v.slice(0, 30) });
                }
              } catch (e) {}

              // 4. Test fetch with SAPISIDHASH auth header (without x-origin)
              try {
                const time = Math.floor(Date.now() / 1000);
                // Compute hash for flow.google.com
                // We'll see if SAPISIDHASH is accepted without x-origin
                const testUrl = 'https://aisandbox-pa.googleapis.com/v1/credits?key=AIzaSyBtrm0o5ab1c-Ec8ZuLcGt3oJAA5VWt3pY';
                const r1 = await fetch(testUrl, {
                  headers: {
                    'authorization': `SAPISIDHASH ${sapisidVal ? time + '_' + sapisidVal.slice(0,10) : ''}`,
                  },
                  credentials: 'include'
                });
                tests.sapisid_no_xorigin = { status: r1.status, text: (await r1.text()).slice(0, 300) };
              } catch (e) { tests.sapisid_no_xorigin = { error: e.message }; }

              return {
                href: window.location.href,
                ya29Found,
                wizKeys: window.WIZ_global_data ? Object.keys(window.WIZ_global_data) : [],
                tests
              };
            },
            args: [sapisid]
          });
          sendToAgent({
            id: msg.id,
            result: {
              flowKey,
              hasSapisid: !!sapisid,
              authHdrPrefix: authHdr ? authHdr.slice(0, 25) : null,
              tabResult: results?.[0]?.result
            }
          });
        } catch (e) {
          sendToAgent({ id: msg.id, error: e.message });
        }
      } else if (msg.method === 'open_flow_tab') {
        // Python bridge asks us to open/focus a Flow tab
        // If token is still fresh, just send it back — no need to open/reload
        if (isTokenFresh()) {
          console.log('[Flow Agent] open_flow_tab: token fresh, sending cached token');
          sendToAgent({ type: 'token_captured', flowKey, clientId: extensionClientId });
        } else {
          console.log('[Flow Agent] open_flow_tab: token missing/expired, opening tab');
          // Reloading an existing flow.google.com tab never yields a bearer —
          // only the labs.google handoff does.
          await refreshTokenViaLabs();
          await sleep(5000);
          if (flowKey && ws?.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'token_captured', flowKey }));
            console.log('[Flow Agent] Sent token after tab open');
          } else {
            const data = await chrome.storage.local.get(['flowKey']);
            if (data.flowKey) {
              flowKey = data.flowKey;
              if (ws?.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({ type: 'token_captured', flowKey }));
                console.log('[Flow Agent] Sent token from storage after tab open');
              }
            }
          }
        }
      } else if (msg.method === 'refresh_flow_tab' || msg.method === 'force_refresh') {
        // Python bridge asks us to refresh token.
        // force_refresh (or an explicit msg.force) bypasses the freshness check:
        // Google can invalidate a token via inactivity long before its 50-min
        // age limit, so a "fresh" token may still be dead (401). In that case we
        // must actually reload the tab and re-capture, not resend the cached one.
        const force = msg.force === true || msg.method === 'force_refresh';
        if (isTokenFresh() && !force) {
          console.log('[Flow Agent] refresh_flow_tab: token fresh, sending cached token');
          if (ws?.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'token_captured', flowKey }));
          }
        } else {
          console.log('[Flow Agent] refresh_flow_tab: forcing tab reload + re-capture');
          // Drop the stale token so captureTokenFromFlowTab can't short-circuit.
          if (force) {
            flowKey = null;
            metrics.tokenCapturedAt = null;
          }
          await captureTokenFromFlowTab();
          await sleep(3000);
          if (flowKey && ws?.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'token_captured', flowKey }));
            console.log('[Flow Agent] Sent token after refresh');
          } else {
            const data = await chrome.storage.local.get(['flowKey']);
            if (data.flowKey) {
              flowKey = data.flowKey;
              if (ws?.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({ type: 'token_captured', flowKey }));
                console.log('[Flow Agent] Sent token from storage after refresh');
              }
            }
          }
        }
      } else if (msg.type === 'callback_config') {
        callbackSecret = msg.secret;
        callbackUrl = normalizeCallbackUrl(msg.callback_url);
        chrome.storage.local.set({ callbackSecret: msg.secret, callbackUrl });
        console.log('[Flow Agent] Received callback config:', callbackUrl);
      } else if (msg.type === 'callback_secret') {
        callbackSecret = msg.secret;
        chrome.storage.local.set({ callbackSecret: msg.secret });
        console.log('[Flow Agent] Received callback secret');
      } else if (msg.type === 'pong') {
        // keepalive response
      }
    } catch (e) {
      console.error('[Flow Agent] Message error:', e);
    }
  };

  ws.onclose = () => {
    stopWsPing();
    setState('off');
    if (!manualDisconnect) scheduleReconnect();
  };

  ws.onerror = (e) => {
    console.error('[Flow Agent] WS error:', e);
    metrics.lastError = 'WS_ERROR';
    chrome.storage.local.set({ metrics });
  };
}

function agentHttpBase() {
  const host = String(connectedServerHost || CONFIG.DEFAULT_SERVER_HOST).trim().replace(/\/$/, '');
  const hostWithoutScheme = host.replace(/^https?:\/\//i, '');
  const local = /^(127\.0\.0\.1|localhost|192\.168\.|10\.)(:|$)/.test(hostWithoutScheme);
  return /^https?:\/\//i.test(host) ? host : `${local ? 'http' : 'https'}://${host}`;
}

async function connectHttpAgent() {
  if (manualDisconnect || httpConnected) return;
  const storage = await chrome.storage.local.get(['clientId']);
  let clientId = storage.clientId;
  if (!clientId) {
    const prefix = CONFIG.DEFAULT_CLIENT_ID_PREFIX || 'client';
    clientId = `${prefix}-${Math.random().toString(36).substring(2, 8)}`;
    await chrome.storage.local.set({ clientId });
  }
  extensionClientId = clientId;
  connectedServerHost = CONFIG.DEFAULT_SERVER_HOST;
  await ensureAuthCaptured();
  try {
    const response = await fetch(`${agentHttpBase()}/api/ext/hello`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        session_id: clientId,
        clientId,
        flowKey,
        flowKeyPresent: !!flowKey,
        extension_version: chrome.runtime.getManifest().version,
      }),
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    callbackSecret = data.secret;
    callbackUrl = new URL(data.callback_url, agentHttpBase()).toString();
    httpPollIntervalMs = Math.max(250, Number(data.poll_interval_ms) || 1000);
    httpConnected = true;
    await chrome.storage.local.set({ callbackSecret, callbackUrl });
    setState('idle');
    scheduleHttpPoll(0);
    flushOutbox();
  } catch (error) {
    httpConnected = false;
    console.warn('[Flow Agent] HTTP bridge unavailable; using WebSocket fallback:', error.message);
  }
}

function scheduleHttpPoll(delay = httpPollIntervalMs) {
  if (httpPollTimer) clearTimeout(httpPollTimer);
  if (!httpConnected || manualDisconnect) return;
  httpPollTimer = setTimeout(pollHttpCommands, delay);
}

async function pollHttpCommands() {
  if (!httpConnected || manualDisconnect) return;
  try {
    const response = await fetch(`${agentHttpBase()}/api/ext/poll?session_id=${encodeURIComponent(extensionClientId)}`, {
      headers: { Authorization: `Bearer ${callbackSecret}` },
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    const commands = data.commands || [];
    if (commands.length > 0 && typeof ws?.onmessage === 'function') {
      commands.forEach((command) => {
        Promise.resolve(ws.onmessage({ data: JSON.stringify(command) })).catch((err) => {
          console.error('[Flow Agent] Command execution error:', err);
        });
      });
    }
    scheduleHttpPoll();
  } catch (error) {
    httpConnected = false;
    console.warn('[Flow Agent] HTTP polling stopped:', error.message);
    scheduleReconnect();
  }
}

function scheduleReconnect() {
  chrome.alarms.create('reconnect', { delayInMinutes: 0.5 });
}

function keepAlive() {
  if (httpConnected) {
    connectHttpAgent();
  } else if (ws?.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ type: 'ping' }));
  } else {
    connectToAgent();
  }
}

function sendToAgent(msg) {
  if (msg.id) {
    if (ws?.readyState === WebSocket.OPEN) {
      try {
        ws.send(JSON.stringify(msg));
      } catch (e) {
        console.warn('[Flow Agent] WS send error:', e.message);
      }
    }
    enqueueResponse(msg);
    return;
  }
  if (httpConnected && callbackSecret) {
    fetch(callbackUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${callbackSecret}` },
      body: JSON.stringify({ ...msg, session_id: extensionClientId }),
    }).catch(() => {});
  } else if (ws?.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(msg));
  }
}

// ─── Durable Response Outbox ────────────────────────────────
// A generated image/video result must survive a momentary backend hiccup or a
// service-worker restart. Every id-bearing response is persisted and retried
// with backoff until the agent confirms receipt, then dropped.

const MAX_DELIVERY_ATTEMPTS = 8;
let outbox = {};              // id -> { msg, attempts, nextAt }
let _flushingOutbox = false;

async function loadOutbox() {
  try {
    const { responseOutbox } = await chrome.storage.local.get('responseOutbox');
    if (responseOutbox && typeof responseOutbox === 'object') outbox = responseOutbox;
  } catch { }
}

function persistOutbox() {
  chrome.storage.local.set({ responseOutbox: outbox }).catch(() => { });
}

function enqueueResponse(msg) {
  outbox[msg.id] = { msg, attempts: 0, nextAt: 0 };
  persistOutbox();
  flushOutbox();
}

async function deliverOnce(entry) {
  try {
    const serverIp = connectedServerHost || CONFIG.DEFAULT_SERVER_HOST;
    const targetCallbackUrl = normalizeCallbackUrl(serverIp);

    const resp = await fetch(targetCallbackUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(callbackSecret ? { Authorization: `Bearer ${callbackSecret}` } : {}),
      },
      body: JSON.stringify({ ...entry.msg, session_id: extensionClientId }),
      // A stalled delivery must not wedge flushOutbox (and every response behind it).
      signal: AbortSignal.timeout(30000),
    });
    // Any HTTP reply means the backend is reachable and has taken the response
    // (ok:true = matched a request, ok:false = unknown id / already handled).
    // Either way there is nothing to retry — only transport failures retry.
    if (resp.ok) return true;
    // 5xx / transient server error — retry.
    return false;
  } catch {
    // Network error: backend unreachable. Try WS as an immediate fallback but
    // keep the entry queued so a later flush can still deliver it.
    if (ws?.readyState === WebSocket.OPEN) {
      try { ws.send(JSON.stringify(entry.msg)); } catch { }
    }
    return false;
  }
}

async function flushOutbox() {
  if (_flushingOutbox) return;
  _flushingOutbox = true;
  try {
    const ids = Object.keys(outbox);
    if (!ids.length) return;
    const now = Date.now();
    for (const id of ids) {
      const entry = outbox[id];
      if (!entry) continue;
      if (entry.nextAt && entry.nextAt > now) continue;
      const delivered = await deliverOnce(entry);
      if (delivered) {
        delete outbox[id];
        persistOutbox();
        continue;
      }
      entry.attempts++;
      if (entry.attempts >= MAX_DELIVERY_ATTEMPTS) {
        console.error('[Flow Agent] Dropping response', id, 'after', entry.attempts, 'failed deliveries');
        delete outbox[id];
      } else {
        // Exponential backoff, capped at 30s.
        entry.nextAt = Date.now() + Math.min(30000, 1000 * 2 ** entry.attempts);
      }
      persistOutbox();
    }
  } finally {
    _flushingOutbox = false;
  }
}

// ─── reCAPTCHA Solving ──────────────────────────────────────

async function requestCaptchaFromTab(tabId, requestId, pageAction) {
  try {
    return await chrome.tabs.sendMessage(tabId, {
      type: 'GET_CAPTCHA',
      requestId,
      pageAction,
    });
  } catch (error) {
    const msg = error?.message || '';
    const shouldInject =
      msg.includes('Receiving end does not exist') ||
      msg.includes('Could not establish connection');
    if (!shouldInject) throw error;

    // Inject content script and retry
    const tab = await chrome.tabs.get(tabId);
    if (!isFlowUrl(tab?.url)) throw new Error('INVALID_FLOW_TAB');
    await chrome.scripting.executeScript({
      target: { tabId },
      files: ['content.js'],
    });
    await sleep(200);
    return await chrome.tabs.sendMessage(tabId, {
      type: 'GET_CAPTCHA',
      requestId,
      pageAction,
    });
  }
}

async function solveCaptcha(requestId, captchaAction, projectId) {
  let tab = await getOrOpenFlowTab(projectId);
  // reCAPTCHA only loads on /project/ pages — a home-page tab can never solve.
  tab = await ensureProjectPage(tab);
  if (!tab) return { error: 'NO_FLOW_TAB' };
  console.log('[Flow Agent] Solving captcha', captchaAction, 'in tab', tab.id, tab.url);

  try {
    const resp = await Promise.race([
      requestCaptchaFromTab(tab.id, requestId, captchaAction),
      new Promise((_, rej) => setTimeout(() => rej(new Error('CAPTCHA_TIMEOUT')), 30000)),
    ]);
    return resp;
  } catch (e) {
    return { error: e.message };
  }
}

async function handleSolveCaptcha(msg) {
  const { id, params } = msg;
  const result = await solveCaptcha(id, params?.captchaAction || 'VIDEO_GENERATION', params?.projectId);

  // Standalone captcha solve counts as captcha-consuming
  metrics.requestCount++;
  if (result?.token) {
    metrics.successCount++;
  } else {
    metrics.failedCount++;
    metrics.lastError = result?.error || 'NO_TOKEN';
  }
  chrome.storage.local.set({ metrics });

  sendToAgent({ id, result });
}

// ─── API Request Proxy ──────────────────────────────────────

async function handleTrpcRequest(msg) {
  const { id, params } = msg;
  const { url, method = 'POST', headers = {}, body } = params;

  if (!url || !(url.startsWith('https://labs.google/') || url.startsWith('https://flow.google.com/'))) {
    sendToAgent({ id, error: 'INVALID_TRPC_URL' });
    return;
  }

  setState('running');
  // TRPC calls don't consume captcha and are silent — no metrics, no request log.

  const fetchHeaders = { 'Content-Type': 'application/json', ...headers };
  if (flowKey) {
    fetchHeaders['authorization'] = `Bearer ${flowKey}`;
  }

  try {
    const resp = await fetch(url, {
      method,
      headers: fetchHeaders,
      body: body ? JSON.stringify(body) : undefined,
      credentials: 'include',
    });
    const data = await resp.json();
    sendToAgent({ id, status: resp.status, data });
  } catch (e) {
    console.error('[Flow Agent] tRPC request failed:', e);
    sendToAgent({ id, error: e.message || 'TRPC_FETCH_FAILED' });
  } finally {
    setState('idle');
  }
}


async function handleUploadVideo(msg) {
  const { id, params } = msg;
  const { videoBase64, projectId, videoSize } = params;

  try {
    const tabs = await chrome.tabs.query({ url: FLOW_TAB_URLS });
    if (!tabs.length) {
      sendToAgent({ id, error: 'NO_FLOW_TAB' });
      return;
    }

    const size = videoSize || (videoBase64 ? Math.floor(videoBase64.length * 3 / 4) : 0);

    // Get session URL via page context XHR (needs session cookies)
    const startResults = await chrome.scripting.executeScript({
      target: { tabId: tabs[0].id },
      world: 'MAIN',
      func: (projId, sz) => {
        return new Promise((resolve) => {
          const xhr = new XMLHttpRequest();
          xhr.open('POST', '/fx/api/upload-video?action=start');
          xhr.setRequestHeader('X-Upload-Project-Id', projId);
          xhr.setRequestHeader('X-Upload-Content-Type', 'video/mp4');
          xhr.setRequestHeader('X-Upload-Content-Length', sz.toString());
          xhr.withCredentials = true;
          xhr.onload = () => {
            let data;
            try { data = JSON.parse(xhr.responseText); } catch { data = {}; }
            resolve({
              sessionUrl: data.sessionUrl || xhr.getResponseHeader('X-Upload-Session-Url') || '',
              status: xhr.status,
            });
          };
          xhr.onerror = () => resolve({ error: 'POST_FAILED' });
          xhr.send();
        });
      },
      args: [projectId, size],
    });

    const step1 = startResults?.[0]?.result;
    if (!step1 || step1.error || !step1.sessionUrl) {
      sendToAgent({ id, error: step1?.error || 'NO_SESSION_URL' });
      return;
    }

    // Return sessionUrl + token — caller handles PUT
    sendToAgent({
      id,
      result: {
        sessionUrl: step1.sessionUrl,
        token: flowKey || '',
      },
    });
  } catch (e) {
    sendToAgent({ id, error: `UPLOAD_ERROR: ${e.message}` });
  }
}

// ─── In-page video submit (runs in MAIN world via executeScript) ──
// Must be fully self-contained: no closure variables allowed.
async function flowDomSubmitVideo(promptText, aspectVal, modelKey) {
  const sleep = (ms) => new Promise(r => setTimeout(r, ms));
  const pick = (sel, root = document) => root.querySelector(sel);
  const all = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  const overlay = () => document.querySelector('.cdk-overlay-container');
  const overlayItems = () => all('button, [role="menuitem"], [role="menuitemradio"], [role="option"], [role="radio"], flow-menu-item, mat-option, li', overlay() || document);

  try {
    // 1. Dismiss overlays that block clicks: cookie bar, onboarding, drawer.
    const reject = all('button').find(b => /glue-cookie-notification-bar__reject/.test(b.className) || (b.innerText || '').trim() === 'No thanks');
    const accept = all('button').find(b => /glue-cookie-notification-bar__accept/.test(b.className) || (b.innerText || '').trim() === 'Agree');
    (reject || accept)?.click();
    await sleep(400);
    const gotIt = all('button').find(b => (b.getAttribute('aria-label') || '').includes('dismiss onboarding') || (b.innerText || '').includes('Got it'));
    if (gotIt) { gotIt.click(); await sleep(400); }
    for (const label of ['Close', 'Back']) {
      const hb = all('button.header-action').find(b => b.getAttribute('aria-label') === label);
      if (hb) { hb.click(); await sleep(600); }
    }

    // 2. Agent mode OFF — it locks generation to agentic Omni flow.
    const chip = pick('.agent-mode-chip');
    if (chip && chip.className.includes('checked')) {
      chip.click();
      await sleep(700);
    }

    // 3. Wait for the ProseMirror editor (Angular mounts async) — prefer the
    //    one inside a VISIBLE prompt box (drawer mounts a hidden duplicate).
    const findEditor = () => all('.ProseMirror, [contenteditable="true"], [role="textbox"]')
      .find(e => e.offsetParent !== null)
      || pick('.ProseMirror') || pick('[contenteditable="true"]') || pick('[role="textbox"]');
    let editor = findEditor();
    for (let i = 0; !editor && i < 40; i++) { await sleep(500); editor = findEditor(); }
    if (!editor) return { ok: false, error: 'NO_EDITOR' };
    const promptBox = editor.closest('flow-base-prompt-box') || document;

    // 4. Open quick settings — scoped to the same prompt box (retry while the
    //    trigger is hidden during drawer nav).
    let trigger = null;
    for (let i = 0; i < 20; i++) {
      trigger = all('.settings-trigger-button', promptBox).find(b => !b.hidden && b.offsetParent !== null);
      if (trigger) break;
      await sleep(400);
    }
    if (!trigger) return { ok: false, error: 'NO_SETTINGS_TRIGGER' };
    trigger.click();
    await sleep(900);

    // 5. Switch mode to Video.
    const videoMode = overlayItems().find(el => {
      const t = (el.innerText || '').trim();
      return t === 'Video' || /videocam[\s|]*Video/i.test(t);
    });
    if (!videoMode) return { ok: false, error: 'NO_VIDEO_MODE_OPTION' };
    videoMode.click();
    await sleep(900);

    // 6. Model family → Veo variant (default Fast per project rules).
    const wanted = /quality/i.test(modelKey) ? 'Quality' : /lite/i.test(modelKey) ? 'Lite' : 'Fast';
    const modelBtn = overlayItems().find(b =>
      b.getAttribute('aria-label') === 'Select model family' || (b.innerText || '').includes('arrow_drop_down'));
    if (modelBtn) {
      modelBtn.click();
      await sleep(900);
      const item = overlayItems().find(el => {
        const t = (el.innerText || '').trim();
        return /veo/i.test(t) && new RegExp(wanted, 'i').test(t) && !/lower priority/i.test(t);
      }) || overlayItems().find(el => /veo/i.test(el.innerText || '') && !/lower priority/i.test(el.innerText || ''));
      if (item) { item.click(); await sleep(700); }
    }

    // 7. Aspect ratio.
    const portrait = /portrait|9_16|9:16/i.test(aspectVal || '');
    const aspectRe = portrait ? /crop_9_16|9:16/ : /crop_16_9|16:9/;
    const aspectBtn = overlayItems().find(el => el.getAttribute('role') === 'radio' && aspectRe.test(el.innerText || ''));
    if (aspectBtn) { aspectBtn.click(); await sleep(500); }

    // 8. Close the panel.
    document.body.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', code: 'Escape', bubbles: true }));
    await sleep(400);
    document.body.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', code: 'Escape', bubbles: true }));
    await sleep(400);

    // 9. Baseline of existing media URLs (for later completion diffing).
    const baseline = new Set();
    for (const el of document.querySelectorAll('video[src], video source[src], img[src], [poster]')) {
      const v = el.src || el.getAttribute('src') || el.getAttribute('poster') || '';
      if (v) baseline.add(v);
    }
    for (const e of performance.getEntriesByType('resource')) {
      if (e.name.includes('flow-content.google')) baseline.add(e.name);
    }

    // 10. Type the prompt. Pick the editor inside a VISIBLE prompt box —
    //     the settings drawer mounts a second, hidden prompt box.
    editor = findEditor() || editor;
    editor.focus();
    document.execCommand('selectAll', false, null);
    document.execCommand('insertText', false, promptText);
    editor.dispatchEvent(new Event('input', { bubbles: true }));
    await sleep(500);

    // 11. Generate button inside the SAME prompt box (waits for enable).
    let genBtn = null;
    for (let i = 0; i < 15; i++) {
      genBtn = pick('.generate-icon-button', promptBox)
        || all('button', promptBox).find(b => (b.getAttribute('aria-label') || '').toLowerCase().includes('start generation'));
      if (genBtn && !genBtn.disabled) break;
      await sleep(400);
    }
    if (!genBtn || genBtn.disabled) return { ok: false, error: 'BUTTON_DISABLED_OR_MISSING' };
    genBtn.click();

    // 12. Confirm the submission registered — spinner/progress/new card.
    for (let i = 0; i < 40; i++) {
      await sleep(500);
      const busy = document.querySelector('[class*="progress"], [class*="spinner"], mat-progress-bar, mat-spinner, [role="progressbar"]');
      const toast = document.querySelector('mat-snack-bar-container, [role="alert"]');
      if (toast && (toast.innerText || '').trim()) {
        return { ok: false, error: (toast.innerText || '').trim().slice(0, 300) };
      }
      if (busy) return { ok: true, baseline: [...baseline] };
      // some builds show no spinner — a new video/img URL counts too
      const fresh = Array.from(document.querySelectorAll('video[src], img[src]'))
        .map(el => el.src).filter(u => u && !baseline.has(u));
      if (fresh.length) return { ok: true, baseline: [...baseline] };
    }
    // No visible progress signal, but the click landed — report success and let
    // the poll loop confirm via the media grid.
    return { ok: true, baseline: [...baseline] };
  } catch (e) {
    return { ok: false, error: String(e && e.message || e) };
  }
}

async function handleApiRequest(msg) {
  const { id, params } = msg;
  const { url, method, headers, body, captchaAction } = params;

  if (!url) {
    sendToAgent({ id, error: 'MISSING_URL' });
    return;
  }

  if (url.includes('/v1/credits') || url.endsWith('/credits')) {
    sendToAgent({
      id,
      status: 200,
      data: {
        credits: 100,
        userPaygateTier: 'PAYGATE_TIER_ONE',
        sku: 'G1_PRO'
      }
    });
    setState('idle');
    return;
  }

  // ─── DOM-driven video generation (T2V) ─────────────────────
  // The new flow.google.com frontend uses cookie-authenticated batchexecute
  // RPCs; the aisandbox-pa REST endpoint rejects page-origin calls (XD3). So
  // video generation is driven through the project page UI instead: agent
  // chip off → quick settings → "Video" mode → Veo model + aspect → prompt →
  // generate. Submit returns a synthetic media id; completion is observed via
  // the poll_status interception below (scanning the grid for the new
  // flow-content URL), and get_media_url serves the captured URL.
  if (url.includes('batchAsyncGenerateVideoText')) {
    setState('running');
    metrics.requestCount++;
    const req0 = body?.requests?.[0] || {};
    const prompt = req0?.textInput?.structuredPrompt?.parts?.[0]?.text
      || req0?.structuredPrompt?.parts?.[0]?.text
      || body?.prompt || '';
    const aspect = req0?.aspectRatio || 'VIDEO_ASPECT_RATIO_PORTRAIT';
    const modelKey = req0?.videoModelKey || '';
    const projectId = body?.clientContext?.projectId || req0?.clientContext?.projectId || null;
    let tab = (await getAnyFlowTab()) || (await getOrOpenFlowTab(projectId));
    tab = await ensureProjectPage(tab);
    if (!tab) {
      sendToAgent({ id, status: 503, error: 'NO_FLOW_TAB' });
      metrics.failedCount++;
      setState('idle');
      return;
    }
    try {
      try { await chrome.tabs.update(tab.id, { active: true }); } catch { }
      const execResults = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: flowDomSubmitVideo,
        args: [prompt, aspect, modelKey],
      });
      const genRes = execResults?.[0]?.result;
      if (genRes?.ok) {
        const mediaId = `domvid_${crypto.randomUUID()}`;
        const jobs = (await chrome.storage.session.get('domVideoJobs'))?.domVideoJobs || [];
        jobs.push({ id: mediaId, status: 'pending', url: null, error: null, baseline: genRes.baseline || [], ts: Date.now() });
        await chrome.storage.session.set({ domVideoJobs: jobs.slice(-10) });
        metrics.successCount++;
        chrome.storage.local.set({ metrics });
        sendToAgent({ id, status: 200, data: { media: [{ name: mediaId }] } });
      } else {
        metrics.failedCount++;
        metrics.lastError = genRes?.error || 'VIDEO_GEN_FAILED';
        chrome.storage.local.set({ metrics });
        sendToAgent({ id, status: 500, error: genRes?.error || 'VIDEO_GEN_FAILED' });
      }
    } catch (err) {
      metrics.failedCount++;
      metrics.lastError = err.message;
      chrome.storage.local.set({ metrics });
      sendToAgent({ id, status: 500, error: err.message });
    }
    setState('idle');
    return;
  }

  // ─── DOM poll for DOM-driven video jobs ────────────────────
  if (url.includes('batchCheckAsyncVideoGenerationStatus')) {
    const name = body?.media?.[0]?.name || '';
    const jobs = (await chrome.storage.session.get('domVideoJobs'))?.domVideoJobs || [];
    const job = jobs.find(j => j.id === name);
    if (!job) {
      // Unknown id — let the request fall through to the API proxy path below.
      // (Can't `continue` here; emulate the upstream behavior by fetching.)
      sendToAgent({ id, status: 404, error: 'UNKNOWN_MEDIA_ID' });
      return;
    }
    try {
      const tab = (await getAnyFlowTab()) || (await getOrOpenFlowTab());
      if (tab) {
        const res = await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          world: 'MAIN',
          func: async (baseline) => {
            const sleep = (ms) => new Promise(r => setTimeout(r, ms));
            const collect = () => {
              const urls = new Set();
              for (const el of document.querySelectorAll('video[src], video source[src], img[src], [src], [poster]')) {
                const v = el.src || el.getAttribute('src') || el.getAttribute('poster') || '';
                if (v) urls.add(v);
              }
              for (const e of performance.getEntriesByType('resource')) {
                if (e.name.includes('flow-content.google')) urls.add(e.name);
              }
              return [...urls];
            };
            const isStrictVid = (u) => /flow-content\.google\/video\//.test(u) || /\.mp4(\?|$)/i.test(u);
            // Posters land first; hover fresh tiles so the real video loads.
            const targets = new Set();
            for (const img of document.querySelectorAll('img[src]')) {
              if (img.src && !baseline.includes(img.src)) targets.add(img.closest('[class*="tile"]') || img);
            }
            for (const t of [...targets].slice(0, 4)) {
              try {
                t.scrollIntoView({ block: 'center' });
                await sleep(400);
                for (const type of ['pointerover', 'mouseover', 'mouseenter']) {
                  t.dispatchEvent(new MouseEvent(type, { bubbles: type !== 'mouseenter', cancelable: true }));
                }
                await sleep(2500);
              } catch { }
            }
            const fresh = collect().filter(u => !baseline.includes(u));
            const videoUrl = fresh.find(isStrictVid) || null;
            const toast = document.querySelector('mat-snack-bar-container, [role="alert"], .error-message');
            return {
              videoUrl,
              error: toast && toast.innerText?.trim() ? toast.innerText.trim().slice(0, 300) : null,
            };
          },
          args: [job.baseline || []],
        });
        const out = res?.[0]?.result || {};
        if (out.videoUrl && job.status !== 'done') {
          job.status = 'done';
          job.url = out.videoUrl;
          await chrome.storage.session.set({ domVideoJobs: jobs });
        }
        if (out.error && job.status === 'pending') {
          job.status = 'failed';
          job.error = out.error;
          await chrome.storage.session.set({ domVideoJobs: jobs });
        }
      }
    } catch { }
    const status = job.status === 'done' ? 'MEDIA_GENERATION_STATUS_SUCCESSFUL'
      : job.status === 'failed' ? 'MEDIA_GENERATION_STATUS_FAILED'
      : 'MEDIA_GENERATION_STATUS_PENDING';
    sendToAgent({
      id,
      status: 200,
      data: {
        media: [{
          name,
          mediaMetadata: { mediaStatus: { mediaGenerationStatus: status } },
        }],
      },
    });
    return;
  }

  if (captchaAction === 'IMAGE_GENERATION' || url.includes('batchGenerateImages')) {
    setState('running');
    metrics.requestCount++;
    const prompt = body?.requests?.[0]?.structuredPrompt?.parts?.[0]?.text || body?.prompt || '';
    const aspect = body?.requests?.[0]?.imageAspectRatio || 'IMAGE_ASPECT_RATIO_SQUARE';
    const projectId = body?.clientContext?.projectId || body?.requests?.[0]?.clientContext?.projectId || null;
    let tab = (await getAnyFlowTab()) || (await getOrOpenFlowTab(projectId));
    tab = await ensureProjectPage(tab);
    if (!tab) {
      sendToAgent({ id, status: 503, error: 'NO_FLOW_TAB' });
      metrics.failedCount++;
      setState('idle');
      return;
    }
    try {
      try {
        await chrome.tabs.update(tab.id, { active: true });
      } catch {}

      const execResults = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: async (promptText, aspectVal) => {
          try {
            // The Angular app mounts the editor asynchronously after the
            // /project/ route resolves — poll instead of failing on first paint.
            // Prefer the editor inside a VISIBLE prompt box — the settings
            // drawer mounts a second, hidden one.
            const findEditor = () =>
              Array.from(document.querySelectorAll('.ProseMirror, [contenteditable="true"], [role="textbox"]'))
                .find(e => e.offsetParent !== null)
              || document.querySelector('.ProseMirror, [contenteditable="true"], [role="textbox"]');
            let editor = findEditor();
            for (let i = 0; !editor && i < 40; i++) {
              await new Promise(r => setTimeout(r, 500));
              editor = findEditor();
            }
            if (!editor) return { ok: false, error: 'NO_EDITOR' };
            const promptBox = editor.closest('flow-base-prompt-box') || document;

            // 1. Dismiss overlays & normalize mode — cookie bar, onboarding,
            //    settings drawer, and the Agent chip (locks to Omni agent flow).
            const cookieBtn = Array.from(document.querySelectorAll('button')).find(b =>
              /glue-cookie-notification-bar__reject/.test(b.className) || (b.innerText || '').trim() === 'No thanks')
              || Array.from(document.querySelectorAll('button')).find(b => /glue-cookie-notification-bar__accept/.test(b.className));
            if (cookieBtn) { cookieBtn.click(); await new Promise(r => setTimeout(r, 300)); }
            const gotIt = Array.from(document.querySelectorAll('button')).find(b =>
              (b.getAttribute('aria-label') || '').includes('dismiss onboarding') || (b.innerText || '').includes('Got it'));
            if (gotIt) { gotIt.click(); await new Promise(r => setTimeout(r, 300)); }
            for (const label of ['Close', 'Back']) {
              const hb = Array.from(document.querySelectorAll('button.header-action')).find(b => b.getAttribute('aria-label') === label);
              if (hb) { hb.click(); await new Promise(r => setTimeout(r, 500)); }
            }
            const agentChip = document.querySelector('.agent-mode-chip');
            if (agentChip && agentChip.className.includes('checked')) {
              agentChip.click();
              await new Promise(r => setTimeout(r, 700));
            }

            // 2. Quick settings → Image mode + aspect ratio.
            const overlayItems = () => Array.from((document.querySelector('.cdk-overlay-container') || document)
              .querySelectorAll('button, [role="menuitem"], [role="menuitemradio"], [role="option"], [role="radio"], flow-menu-item, mat-option, li'));

            let targetAspect = '1:1';
            let targetCrop = 'crop_square';
            if (typeof aspectVal === 'string') {
              const a = aspectVal.toLowerCase();
              if (a.includes('portrait') || a.includes('9_16') || a.includes('9:16')) {
                targetAspect = '9:16'; targetCrop = 'crop_9_16';
              } else if (a.includes('landscape') || a.includes('16_9') || a.includes('16:9')) {
                targetAspect = '16:9'; targetCrop = 'crop_16_9';
              } else if (a.includes('4_3') || a.includes('4:3') || a.includes('4x3')) {
                targetAspect = '4:3'; targetCrop = 'crop_landscape';
              } else if (a.includes('3_4') || a.includes('3:4') || a.includes('3x4')) {
                targetAspect = '3:4'; targetCrop = 'crop_portrait';
              }
            }

            let settingsBtn = null;
            for (let i = 0; i < 20; i++) {
              const t = Array.from((promptBox || document).querySelectorAll('.settings-trigger-button'))
                .find(b => !b.hidden && b.offsetParent !== null)
                || document.querySelector('.settings-trigger-button');
              if (t && !t.hidden && t.offsetParent !== null) { settingsBtn = t; break; }
              await new Promise(r => setTimeout(r, 400));
            }
            if (settingsBtn) {
              settingsBtn.click();
              await new Promise(r => setTimeout(r, 900));

              // Mode → Image (only present when agent chip is off)
              const imgMode = overlayItems().find(el => {
                const t = (el.innerText || '').trim();
                return t === 'Image' || /^image[\s|]*Image$/i.test(t);
              });
              if (imgMode) { imgMode.click(); await new Promise(r => setTimeout(r, 800)); }

              const aspectOption = overlayItems().find(el =>
                el.getAttribute('role') === 'radio' &&
                ((el.innerText || '').includes(targetCrop) || (el.innerText || '').includes(targetAspect)));
              if (aspectOption) { aspectOption.click(); await new Promise(r => setTimeout(r, 400)); }

              document.body.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', code: 'Escape', bubbles: true }));
              await new Promise(r => setTimeout(r, 300));
              document.body.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', code: 'Escape', bubbles: true }));
              await new Promise(r => setTimeout(r, 300));
            }

            // 3. Type prompt into editor
            editor.focus();
            document.execCommand('selectAll', false, null);
            document.execCommand('insertText', false, promptText);
            editor.dispatchEvent(new Event('input', { bubbles: true }));
            editor.dispatchEvent(new Event('change', { bubbles: true }));
            await new Promise(r => setTimeout(r, 400));

            // 4. Find generate button inside the same prompt box
            let generateButton = null;
            for (let i = 0; i < 15; i++) {
              generateButton = (promptBox || document).querySelector('.generate-icon-button')
                || Array.from((promptBox || document).querySelectorAll('button')).find(b =>
                  b.innerText?.includes('arrow_forward') ||
                  (b.getAttribute('aria-label') || '').toLowerCase().includes('start generation'));
              if (generateButton && !generateButton.disabled) break;
              await new Promise(r => setTimeout(r, 300));
            }

            if (!generateButton || generateButton.disabled) {
              return { ok: false, error: 'BUTTON_DISABLED_OR_MISSING' };
            }

            // 4. Remember existing images & network entries
            const beforeImgs = new Set(Array.from(document.querySelectorAll('img')).map(i => i.src));
            const beforePerf = new Set(performance.getEntriesByType('resource').map(r => r.name));

            // 5. Click generate!
            generateButton.click();

            // 6. Poll for new image
            let newImageSrc = null;
            for (let i = 0; i < 60; i++) {
              await new Promise(r => setTimeout(r, 1000));

              // Check DOM img tags
              const currentImgs = Array.from(document.querySelectorAll('img')).map(img => img.src);
              const foundDom = currentImgs.find(src => 
                (src.includes('flow-content.google') || src.includes('/asb/') || (src.includes('flow.google.com') && !src.includes('gstatic'))) && 
                !src.includes('avatar') && 
                !src.includes('googleusercontent') && 
                !src.includes('gstatic') && 
                !beforeImgs.has(src)
              );
              if (foundDom) {
                newImageSrc = foundDom;
                break;
              }

              // Check performance entries
              const currentPerf = performance.getEntriesByType('resource').map(r => r.name);
              const foundPerf = currentPerf.reverse().find(src =>
                (src.includes('flow-content.google/image/') || src.includes('/asb/')) &&
                !src.includes('avatar') &&
                !src.includes('googleusercontent') &&
                !src.includes('gstatic') &&
                !beforePerf.has(src)
              );
              if (foundPerf) {
                newImageSrc = foundPerf;
                break;
              }

              // Check for UI error toasts
              const errorToast = document.querySelector('mat-snack-bar-container, [role="alert"], .error-message');
              if (errorToast && errorToast.innerText?.trim()) {
                return { ok: false, error: errorToast.innerText.trim() };
              }
            }

            if (!newImageSrc) {
              return { ok: false, error: 'GENERATION_TIMEOUT' };
            }

            const mediaId = (newImageSrc.match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i) || [])[0] || `flow_${Date.now()}`;
            return {
              ok: true,
              mediaId,
              imageUrl: newImageSrc
            };
          } catch (e) {
            return { ok: false, error: e.message };
          }
        },
        args: [prompt, aspect]
      });

      const genRes = execResults?.[0]?.result;
      if (genRes?.ok && genRes.imageUrl) {
        metrics.successCount++;
        chrome.storage.local.set({ metrics });
        sendToAgent({
          id,
          status: 200,
          data: {
            media: [
              {
                name: genRes.mediaId,
                image: {
                  generatedImage: {
                    fifeUrl: genRes.imageUrl,
                    imageUri: genRes.imageUrl
                  }
                }
              }
            ]
          }
        });
        setState('idle');
        return;
      } else {
        metrics.failedCount++;
        metrics.lastError = genRes?.error || 'IMAGE_GEN_FAILED';
        chrome.storage.local.set({ metrics });
        sendToAgent({
          id,
          status: 500,
          error: genRes?.error || 'IMAGE_GEN_FAILED'
        });
        setState('idle');
        return;
      }
    } catch (err) {
      metrics.failedCount++;
      metrics.lastError = err.message;
      chrome.storage.local.set({ metrics });
      sendToAgent({ id, status: 500, error: err.message });
      setState('idle');
      return;
    }
  }

  if (!url.startsWith('https://aisandbox-pa.googleapis.com/')) {
    sendToAgent({ id, error: 'INVALID_URL' });
    return;
  }

  setState('running');
  const hasCaptcha = !!captchaAction;
  if (hasCaptcha) metrics.requestCount++;

  const logId = id;
  const logType = _classifyApiUrl(url);
  if (_VISIBLE_TYPES.has(logType)) {
    const payloadSummary = body ? JSON.stringify(body).slice(0, 200) : null;
    addRequestLog({ id: logId, type: logType, time: new Date().toISOString(), status: 'processing', error: null, outputUrl: null, url, payloadSummary });
  }

  try {
    // Step 1: Solve captcha if needed
    let captchaToken = null;
    if (captchaAction) {
      const projectId = body?.clientContext?.projectId || body?.requests?.[0]?.clientContext?.projectId || null;
      const captchaResult = await solveCaptcha(id, captchaAction, projectId);
      captchaToken = captchaResult?.token || null;
      if (!captchaToken) {
        // Cannot proceed without captcha — API will 403
        const err = captchaResult?.error || 'CAPTCHA_FAILED';
        console.error(`[Flow Agent] Captcha failed for ${captchaAction}: ${err}`);
        sendToAgent({ id, status: 403, error: `CAPTCHA_FAILED: ${err}` });
        if (hasCaptcha) { metrics.failedCount++; metrics.lastError = `CAPTCHA_FAILED: ${err}`; }
        chrome.storage.local.set({ metrics });
        updateRequestLog(logId, { status: 'failed', error: `CAPTCHA_FAILED: ${err}` });
        setState('idle');
        return;
      }
    }

    // Step 2: Inject captcha token into body
    let finalBody = body;
    if (captchaToken && finalBody) {
      finalBody = JSON.parse(JSON.stringify(finalBody)); // deep clone
      if (finalBody.clientContext?.recaptchaContext) {
        finalBody.clientContext.recaptchaContext.token = captchaToken;
      }
      if (finalBody.requests && Array.isArray(finalBody.requests)) {
        for (const req of finalBody.requests) {
          if (req.clientContext?.recaptchaContext) {
            req.clientContext.recaptchaContext.token = captchaToken;
          }
        }
      }
    }

    // Step 3: Determine auth header (Bearer ya29.* or SAPISIDHASH)
    let authHeader = await getAuthHeader();
    if (!authHeader) {
      // Try one more time to capture cookie auth
      await ensureAuthCaptured();
      authHeader = await getAuthHeader();
    }

    if (!authHeader) {
      sendToAgent({ id, status: 503, error: 'NO_FLOW_KEY' });
      if (hasCaptcha) { metrics.failedCount++; metrics.lastError = 'NO_FLOW_KEY'; }
      chrome.storage.local.set({ metrics });
      updateRequestLog(logId, { status: 'failed', error: 'NO_FLOW_KEY' });
      setState('idle');
      return;
    }

    const projectId = body?.clientContext?.projectId || body?.requests?.[0]?.clientContext?.projectId || null;
    const tab = (await getAnyFlowTab()) || (await getOrOpenFlowTab(projectId));
    let response;
    let responseData;
    let responseText;
    let proxyDebug = { tabFound: !!tab, tabId: tab?.id, tabUrl: tab?.url };

    if (tab) {
      try {
        const results = await withTimeout(
          chrome.scripting.executeScript({
            target: { tabId: tab.id },
            world: 'MAIN',
            func: async (fetchUrl, fetchMethod, finalBody, authHdr) => {
              try {
                const cleanHeaders = {
                  'accept': '*/*',
                  'content-type': 'application/json',
                  'x-goog-authuser': '0',
                  'x-origin': 'https://flow.google.com',
                };
                if (authHdr) cleanHeaders['authorization'] = authHdr;
                const res = await fetch(fetchUrl, {
                  method: fetchMethod,
                  headers: cleanHeaders,
                  credentials: 'include',
                  body: fetchMethod === 'GET' ? undefined : (typeof finalBody === 'string' ? finalBody : JSON.stringify(finalBody)),
                });
                const text = await res.text();
                let data;
                try { data = JSON.parse(text); } catch { data = text; }
                return { ok: res.ok, status: res.status, data, text };
              } catch (err) {
                return { ok: false, error: err.message };
              }
            },
            args: [url, method || 'POST', finalBody, authHeader],
          }),
          6000,
          'EXEC_SCRIPT'
        );
        const proxyResp = results?.[0]?.result;
        proxyDebug.proxyResp = proxyResp;
        if (proxyResp && proxyResp.status) {
          response = { ok: proxyResp.ok, status: proxyResp.status };
          responseData = proxyResp.data;
          responseText = proxyResp.text || (typeof proxyResp.data === 'string' ? proxyResp.data : JSON.stringify(proxyResp.data));
        }
      } catch (scriptErr) {
        proxyDebug.scriptErr = scriptErr.message;
        console.error('[Flow Agent] executeScript failed:', scriptErr.message);
      }
    }

    // Fallback: If tab execution failed or no tab, try service worker fetch
    if (!response) {
      console.log('[Flow Agent] Tab unavailable; trying service worker fetch...');
      const fetchHeaders = { ...(headers || {}) };
      fetchHeaders['authorization'] = authHeader;
      fetchHeaders['x-origin'] = 'https://flow.google.com';
      fetchHeaders['x-goog-authuser'] = '0';
      const abort = new AbortController();
      const abortTimer = setTimeout(() => abort.abort(), 8000);
      try {
        response = await fetch(url, {
          method: method || 'POST',
          headers: fetchHeaders,
          credentials: 'include',
          body: method === 'GET' ? undefined : JSON.stringify(finalBody),
          signal: abort.signal,
        });
        responseText = await response.text();
        try { responseData = JSON.parse(responseText); } catch { responseData = responseText; }
      } catch (fetchErr) {
        proxyDebug.swFetchErr = fetchErr.message;
        console.warn('[Flow Agent] SW fetch error:', fetchErr.message);
      } finally {
        clearTimeout(abortTimer);
      }
    }

    if (responseData && typeof responseData === 'object') {
      responseData._proxyDebug = proxyDebug;
    }

    if (!response) {
      sendToAgent({ id, status: 500, error: 'FETCH_FAILED' });
      if (hasCaptcha) { metrics.failedCount++; metrics.lastError = 'FETCH_FAILED'; }
      chrome.storage.local.set({ metrics });
      updateRequestLog(logId, { status: 'failed', error: 'FETCH_FAILED' });
      setState('idle');
      return;
    }

    // Self-heal: a 401 means Google invalidated our cached token (usually via
    // inactivity, before our 50-min freshness window). Drop it so the very next
    // request / refresh forces a genuine tab reload + re-capture instead of
    // resending the same dead token.
    if (response.status === 401) {
      console.warn('[Flow Agent] 401 UNAUTHENTICATED:', responseText.slice(0, 200));
      if (flowKey && flowKey.startsWith('ya29.')) {
        flowKey = null;
        metrics.tokenCapturedAt = null;
        chrome.storage.local.set({ flowKey: null });
      }
    }

    sendToAgent({
      id,
      status: response.status,
      data: responseData,
    });

    const responseSummary = responseText ? responseText.slice(0, 300) : null;
    if (response.ok) {
      if (hasCaptcha) { metrics.successCount++; metrics.lastError = null; }
      updateRequestLog(logId, { status: 'success', httpStatus: response.status, responseSummary });
    } else {
      if (hasCaptcha) { metrics.failedCount++; metrics.lastError = `API_${response.status}`; }
      updateRequestLog(logId, { status: 'failed', error: `API_${response.status}`, httpStatus: response.status, responseSummary });
    }
  } catch (e) {
    sendToAgent({
      id,
      status: 500,
      error: e.message || 'API_REQUEST_FAILED',
    });
    if (hasCaptcha) { metrics.failedCount++; metrics.lastError = e.message; }
    updateRequestLog(logId, { status: 'failed', error: e.message || 'API_REQUEST_FAILED' });
  }

  chrome.storage.local.set({ metrics });
  setState('idle');
}

async function handleGetMediaUrl(msg) {
  const { id, params } = msg;
  const mediaId = params?.media_id;
  if (!mediaId) { sendToAgent({ id, error: 'MISSING_MEDIA_ID' }); return; }
  // DOM-driven generation jobs carry their captured flow-content URL directly.
  try {
    const jobs = (await chrome.storage.session.get('domVideoJobs'))?.domVideoJobs || [];
    const job = jobs.find(j => j.id === mediaId);
    if (job?.url) {
      sendToAgent({ id, status: 200, result: { url: job.url } });
      return;
    }
    if (job && !job.url) {
      // Job exists but no URL captured yet — rescan the tab once before failing.
      const tab = await getAnyFlowTab();
      if (tab) {
        try {
          const res = await chrome.scripting.executeScript({
            target: { tabId: tab.id }, world: 'MAIN',
            func: (baseline) => {
              const urls = new Set();
              for (const el of document.querySelectorAll('video[src], video source[src], [poster]')) {
                const v = el.src || el.getAttribute('src') || el.getAttribute('poster') || '';
                if (v) urls.add(v);
              }
              for (const e of performance.getEntriesByType('resource')) {
                if (e.name.includes('flow-content.google')) urls.add(e.name);
              }
              const freshUrls = [...urls].filter(u => !baseline.includes(u));
              return freshUrls.find(u => /flow-content\.google\/video\//.test(u)) || null;
            },
            args: [job.baseline || []],
          });
          const found = res?.[0]?.result;
          if (found) {
            job.url = found; job.status = 'done';
            await chrome.storage.session.set({ domVideoJobs: jobs });
            sendToAgent({ id, status: 200, result: { url: found } });
            return;
          }
        } catch { }
      }
    }
  } catch { }
  try {
    const url = new URL('https://labs.google/fx/api/trpc/media.getMediaUrlRedirect');
    url.searchParams.set('name', mediaId);
    const response = await fetch(url.toString(), { credentials: 'include', redirect: 'follow' });
    if (!response.ok) { sendToAgent({ id, status: response.status, error: `MEDIA_URL_HTTP_${response.status}` }); return; }
    sendToAgent({ id, status: 200, result: { url: response.url } });
  } catch (error) {
    sendToAgent({ id, error: `MEDIA_URL_FAILED: ${error.message}` });
  }
}

// ─── State & Popup ──────────────────────────────────────────

function setState(newState) {
  state = newState;
  const badges = { idle: '●', running: '▶', off: '○' };
  const colors = { idle: '#22c55e', running: '#f59e0b', off: '#6b7280' };
  chrome.action.setBadgeText({ text: badges[state] || '' });
  chrome.action.setBadgeBackgroundColor({ color: colors[state] || '#000' });
  broadcastStatus();
}

function broadcastStatus() {
  chrome.runtime.sendMessage({ type: 'STATUS_PUSH' }).catch(() => { });
}

chrome.runtime.onMessage.addListener((msg, _, reply) => {
  // Page-world Bearer capture relayed by content.js (injected.js sniffs the
  // page's own fetch/XHR Authorization headers — catches tokens emitted on
  // hosts webRequest doesn't cover). ya29 tokens always accepted; other
  // schemes only from trusted Google hosts and only if token-shaped.
  if (msg.type === 'PAGE_BEARER_TOKEN') {
    const url = String(msg.url || '');
    let hostname = '';
    try { hostname = new URL(url, 'https://x.invalid').hostname; } catch { }
    const hostOk = /(^|\.)(googleapis\.com|labs\.google|google\.com)$/i.test(hostname);
    const token = String(msg.token || '').trim();
    const plausible =
      token.startsWith('ya29.') ||
      (hostOk &&
        token.length >= 20 && token.length <= 4096 &&
        /^[A-Za-z0-9._~+\-/=]+$/.test(token) &&
        !/^(null|undefined|none|false|true)$/i.test(token));
    if (plausible) {
      flowKey = token;
      metrics.tokenCapturedAt = Date.now();
      chrome.storage.local.set({ flowKey, metrics });
      console.log(`[Flow Agent] Bearer token captured (page ${hostname})`);
      sendToAgent({ type: 'token_captured', flowKey, clientId: extensionClientId });
      reply({ ok: true });
    } else {
      reply({ ok: false });
    }
    return true;
  }

  if (msg.type === 'SETTINGS_UPDATED') {
    if (ws) {
      try { ws.close(); } catch { }
    }
    connectToAgent();
    reply({ ok: true });
    return true;
  }

  if (msg.type === 'STATUS') {
    reply({
      connected: httpConnected || ws?.readyState === WebSocket.OPEN,
      agentConnected: httpConnected || ws?.readyState === WebSocket.OPEN,
      httpConnected,
      transport: httpConnected ? 'http' : (ws?.readyState === WebSocket.OPEN ? 'ws' : 'none'),
      flowKeyPresent: !!flowKey,
      manualDisconnect,
      tokenAge: metrics.tokenCapturedAt ? Date.now() - metrics.tokenCapturedAt : null,
      metrics: {
        requestCount: metrics.requestCount,
        successCount: metrics.successCount,
        failedCount: metrics.failedCount,
        lastError: metrics.lastError,
      },
      state,
      clientId: extensionClientId,
    });
  }

  if (msg.type === 'DISCONNECT') {
    manualDisconnect = true;
    httpConnected = false;
    if (httpPollTimer) clearTimeout(httpPollTimer);
    if (ws) ws.close();
    reply({ ok: true });
    return true;
  }

  if (msg.type === 'RECONNECT') {
    manualDisconnect = false;
    connectToAgent();
    reply({ ok: true });
    return true;
  }

  if (msg.type === 'REQUEST_LOG') {
    reply({ log: requestLog });
    return true;
  }

  if (msg.type === 'GET_CLIENT_CREDITS') {
    const host = String(connectedServerHost || CONFIG.DEFAULT_SERVER_HOST).trim().replace(/\/$/, '');
    const hostWithoutScheme = host.replace(/^https?:\/\//i, '');
    const local = /^(127\.0\.0\.1|localhost|192\.168\.|10\.)(:|$)/.test(hostWithoutScheme);
    const base = /^https?:\/\//i.test(host) ? host : `${local ? 'http' : 'https'}://${host}`;
    chrome.storage.local.get(['clientId']).then(({ clientId }) => fetch(`${base}/v1/credits`, {
      headers: (extensionClientId || clientId) ? { 'X-Client-Id': extensionClientId || clientId } : {},
    }))
      .then(async (response) => {
        const data = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(data.detail || `HTTP ${response.status}`);
        reply(data);
      })
      .catch((error) => {
        console.error('[Flow Agent] Credit request failed:', error);
        reply({ error: error.message });
      });
    return true;
  }

  if (msg.type === 'CLEAR_REQUEST_LOG') {
    requestLog = [];
    chrome.storage.local.remove('requestLog').then(() => {
      broadcastRequestLog();
      reply({ ok: true });
    });
    return true;
  }

  if (msg.type === 'ADD_HISTORY') {
    addRequestLog({
      id: msg.entry?.id || `popup-${Date.now()}`,
      time: msg.entry?.time || new Date().toISOString(),
      type: msg.entry?.type || 'GEN_IMG',
      status: msg.entry?.status || 'success',
      url: msg.entry?.url || '',
      payloadSummary: msg.entry?.prompt || '',
      responseSummary: msg.entry?.url ? 'Generated result ready' : 'Generation completed',
    });
    reply({ ok: true });
    return true;
  }

  if (msg.type === 'OPEN_FLOW_TAB') {
    chrome.tabs.query({ url: FLOW_TAB_URLS }).then((tabs) => {
      if (tabs.length) {
        chrome.tabs.update(tabs[0].id, { active: true });
        reply({ ok: true, tabId: tabs[0].id });
      } else {
        chrome.tabs.create({ url: FLOW_URL })
          .then((tab) => reply({ ok: true, tabId: tab.id }))
          .catch((e) => reply({ error: e.message }));
      }
    }).catch((e) => reply({ error: e.message }));
    return true;
  }

  if (msg.type === 'REFRESH_TOKEN') {
    captureTokenFromFlowTab()
      .then(() => reply({ ok: true }))
      .catch((e) => reply({ error: e.message }));
    return true;
  }

  if (msg.type === 'TEST_CAPTCHA') {
    solveCaptcha(`test-${Date.now()}`, msg.pageAction || 'IMAGE_GENERATION')
      .then((r) => reply(r))
      .catch((e) => reply({ error: e.message }));
    return true;
  }

  if (msg.type === 'TRPC_MEDIA_URLS') {
    handleTrpcMediaUrls(msg.trpcUrl, msg.body);
    reply({ ok: true });
    return true;
  }

  return true;
});

// ─── TRPC Media URL Extractor ──────────────────────────────

function handleTrpcMediaUrls(trpcUrl, bodyText) {
  try {
    // Extract all fresh GCS signed URLs
    const urlRegex = /https:\/\/(?:storage\.googleapis\.com\/ai-sandbox-videofx|flow-content\.google\/(?:image|video))\/[0-9a-f-]{36}\?[^"'\s]+/g;
    const matches = bodyText.match(urlRegex) || [];
    if (!matches.length) return;

    // Deduplicate and parse
    const urlMap = {};
    for (const rawUrl of matches) {
      // Unescape JSON-escaped URLs
      const url = rawUrl.replace(/\\u0026/g, '&').replace(/\\/g, '');
      const mediaMatch = url.match(/\/(image|video)\/([0-9a-f-]{36})\?/);
      if (mediaMatch) {
        const [, mediaType, mediaId] = mediaMatch;
        // Keep last occurrence (freshest)
        urlMap[mediaId] = { mediaType, url, mediaId };
      }
    }

    const entries = Object.values(urlMap);
    if (!entries.length) return;

    console.log(`[Flow Agent] Captured ${entries.length} fresh media URLs from TRPC`);
    // URL refresh is silent — don't show in request log

    // Forward to agent for DB update
    sendToAgent({ type: 'media_urls_refresh', urls: entries, session_id: extensionClientId });
  } catch (e) {
    console.error('[Flow Agent] Failed to extract TRPC media URLs:', e);
  }
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

// ─── Human-like Telemetry ──────────────────────────────────
// Periodically send tracking events to Google's analytics endpoints
// to mimic normal browser behavior.

const _UA = navigator.userAgent;
let _telemetrySessionId = `;${Date.now()}`;

function _rand(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }

function _buildBatchLogPayload() {
  const events = [];
  const types = ['FLOW_IMAGE_LATENCY', 'FLOW_VIDEO_LATENCY'];
  const count = _rand(1, 3);
  for (let i = 0; i < count; i++) {
    events.push({
      event: types[_rand(0, types.length - 1)],
      eventProperties: [
        { key: 'CURRENT_TIME_MS', doubleValue: Date.now() },
        { key: 'DURATION_MS', doubleValue: _rand(150, 800) },
        { key: 'USER_AGENT', stringValue: _UA },
        { key: 'IS_DESKTOP', booleanValue: true },
      ],
      eventMetadata: { sessionId: _telemetrySessionId },
      eventTime: new Date().toISOString(),
    });
  }
  return { appEvents: events };
}

function _buildFrontendEventsPayload() {
  const eventTypes = [
    'FLOW_IMAGE_LATENCY', 'FLOW_VIDEO_LATENCY', 'GRID_SCROLL_DEPTH',
    'FLOW_PROJECT_OPEN', 'FLOW_SCENE_VIEW',
  ];
  const count = _rand(1, 4);
  const events = [];
  for (let i = 0; i < count; i++) {
    const et = eventTypes[_rand(0, eventTypes.length - 1)];
    const params = {
      USER_AGENT: { '@type': 'type.googleapis.com/google.protobuf.StringValue', value: _UA },
      IS_DESKTOP: { '@type': 'type.googleapis.com/google.protobuf.StringValue', value: 'true' },
    };
    if (et.includes('LATENCY')) {
      params.CURRENT_TIME_MS = { '@type': 'type.googleapis.com/google.protobuf.StringValue', value: String(Date.now()) };
      params.DURATION_MS = { '@type': 'type.googleapis.com/google.protobuf.StringValue', value: String(_rand(100, 600)) };
    }
    if (et === 'GRID_SCROLL_DEPTH') {
      params.MEDIA_GENERATION_PAYGATE_TIER = { '@type': 'type.googleapis.com/google.protobuf.StringValue', value: 'PAYGATE_TIER_TWO' };
    }
    events.push({
      eventType: et,
      metadata: {
        sessionId: _telemetrySessionId,
        createTime: new Date().toISOString(),
        additionalParams: params,
      },
    });
  }
  return { events };
}

async function sendTelemetry() {
  if (!flowKey || state === 'off') return;

  const headers = {
    'Content-Type': 'text/plain;charset=UTF-8',
    'authorization': `Bearer ${flowKey}`,
  };

  // Telemetry is silent — don't show in request log
  try {
    if (Math.random() < 0.5) {
      await fetch(`https://aisandbox-pa.googleapis.com/v1:batchLog`, {
        method: 'POST', headers, credentials: 'include',
        body: JSON.stringify(_buildBatchLogPayload()),
      });
    } else {
      await fetch(`https://aisandbox-pa.googleapis.com/v1/flow:batchLogFrontendEvents`, {
        method: 'POST', headers, credentials: 'include',
        body: JSON.stringify(_buildFrontendEventsPayload()),
      });
    }
  } catch { }
}

// Send telemetry at random intervals (45-120s) to look organic
function scheduleTelemetry() {
  const delay = _rand(45, 120) * 1000;
  setTimeout(async () => {
    await sendTelemetry();
    scheduleTelemetry(); // reschedule with new random interval
  }, delay);
}

// Refresh session ID every ~30min like a real user
setInterval(() => { _telemetrySessionId = `;${Date.now()}`; }, _rand(25, 35) * 60 * 1000);

scheduleTelemetry();

console.log('[Flow Agent] Extension loaded');
