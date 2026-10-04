/**
 * Injected into MAIN world on labs.google — has access to window.grecaptcha
 * Also intercepts TRPC fetch responses to capture fresh signed media URLs.
 */
(() => {
if (window.__FLOW_AGENT_MAIN_INJECTED__) return;
window.__FLOW_AGENT_MAIN_INJECTED__ = true;

const SITE_KEY = '6LdsFiUsAAAAAIjVDZcuLhaHiDn5nnHVXVRQGeMV';

// ─── Bearer Token Intercept ─────────────────────────────────
// Sniff Authorization: Bearer headers on every fetch/XHR the page itself makes
// and forward candidates to the content script — covers any host the page
// talks to, including ones not declared for webRequest.
function _reportBearerToken(token, url) {
  if (!token || typeof token !== 'string') return;
  if (token.length < 20) return;
  window.dispatchEvent(new CustomEvent('FLOW_BEARER_TOKEN', {
    detail: { token, url: String(url || '') },
  }));
}

function _bearerFromHeaders(h) {
  try {
    if (!h) return null;
    let value = null;
    if (h instanceof Headers) value = h.get('authorization');
    else if (Array.isArray(h)) {
      const found = h.find((pair) => String(pair?.[0]).toLowerCase() === 'authorization');
      value = found && found[1];
    } else if (typeof h === 'object') {
      for (const key of Object.keys(h)) {
        if (key.toLowerCase() === 'authorization') { value = h[key]; break; }
      }
    }
    if (!value || !/^Bearer\s+/i.test(value)) return null;
    return value.replace(/^Bearer\s+/i, '').trim();
  } catch {
    return null;
  }
}

// ─── TRPC Response Monitor ─────────────────────────────────
// Monkey-patch fetch to intercept TRPC responses containing media URLs.
// Fresh signed GCS URLs are extracted and forwarded to the agent.

// ─── batchexecute RPC recorder ──────────────────────────────
// The new flow.google.com frontend drives generation through same-origin
// batchexecute POSTs (cookie auth — no Bearer exists). Recording the last few
// request/response pairs lets the extension learn the live RPC contract so it
// can replay generation calls without relying on untrusted DOM clicks.
window.__flowRpcLog = window.__flowRpcLog || [];
function _logRpc(url, bodyText, response) {
  try {
    if (!url.includes('batchexecute') && !url.includes('/_/')) return;
    const entry = { url: String(url).slice(0, 500), body: String(bodyText || '').slice(0, 4000), ts: Date.now() };
    const done = (status, respText) => {
      entry.status = status;
      entry.resp = String(respText || '').slice(0, 2000);
      window.__flowRpcLog.push(entry);
      if (window.__flowRpcLog.length > 12) window.__flowRpcLog.shift();
    };
    response.clone().text().then(t => done(response.status, t)).catch(() => done(response.status, ''));
  } catch {}
}

const _originalFetch = window.fetch;
window.fetch = async function (...args) {
  try {
    const url = typeof args[0] === 'string' ? args[0] : args[0]?.url || '';
    const token = _bearerFromHeaders(args[1]?.headers)
      || _bearerFromHeaders(args[0] instanceof Request ? args[0].headers : null);
    if (token) _reportBearerToken(token, url);
  } catch {}
  let __rpcBody;
  const __rpcUrl = typeof args[0] === 'string' ? args[0] : args[0]?.url || '';
  try {
    if (typeof args[1]?.body === 'string') __rpcBody = args[1].body;
    else if (args[0] instanceof Request && args[0].method !== 'GET') __rpcBody = await args[0].clone().text();
  } catch {}
  const response = await _originalFetch.apply(this, args);
  try {
    _logRpc(__rpcUrl, __rpcBody, response);
  } catch {}
  try {
    const url = typeof args[0] === 'string' ? args[0] : args[0]?.url || '';
    // Only intercept TRPC calls on labs.google that return project/flow data
    if (url.includes('/fx/api/trpc/') && response.ok) {
      const clone = response.clone();
      clone.text().then(text => {
        if (text.includes('storage.googleapis.com/ai-sandbox-videofx/') || text.includes('flow-content.google/')) {
          window.dispatchEvent(new CustomEvent('TRPC_MEDIA_URLS', {
            detail: { url, body: text },
          }));
        }
      }).catch(() => {});
    }
  } catch {}
  return response;
};

// XHR variant — older flows and some SDKs still use XMLHttpRequest.
const _xhrOpen = XMLHttpRequest.prototype.open;
const _xhrSetHeader = XMLHttpRequest.prototype.setRequestHeader;
XMLHttpRequest.prototype.open = function (method, url, ...rest) {
  this.__flowAgentUrl = url;
  return _xhrOpen.call(this, method, url, ...rest);
};
XMLHttpRequest.prototype.setRequestHeader = function (name, value) {
  try {
    if (String(name).toLowerCase() === 'authorization' && /^Bearer\s+/i.test(value)) {
      _reportBearerToken(String(value).replace(/^Bearer\s+/i, '').trim(), this.__flowAgentUrl);
    }
  } catch {}
  return _xhrSetHeader.call(this, name, value);
};

// XHR bodies: batchexecute sometimes travels over XHR — capture request bodies
// and terminal responses into the same ring buffer.
const _xhrSend = XMLHttpRequest.prototype.send;
XMLHttpRequest.prototype.send = function (body) {
  try {
    const u = this.__flowAgentUrl || '';
    if (u.includes('batchexecute') || u.includes('/_/')) {
      const entry = { url: String(u).slice(0, 500), body: String(body || '').slice(0, 4000), ts: Date.now(), xhr: true };
      this.addEventListener('loadend', () => {
        entry.status = this.status;
        try { entry.resp = String(this.responseText || '').slice(0, 2000); } catch {}
        window.__flowRpcLog.push(entry);
        if (window.__flowRpcLog.length > 12) window.__flowRpcLog.shift();
      });
    }
  } catch {}
  return _xhrSend.call(this, body);
};


// Liveness probe so background.js can tell a tab whose bridge actually answers
// from one that merely matches a Flow URL (stale, discarded, or CSP-blocked).
window.addEventListener('FLOW_AGENT_PING', ({ detail }) => {
  window.dispatchEvent(new CustomEvent('FLOW_AGENT_PONG', {
    detail: { requestId: detail?.requestId, grecaptcha: !!window.grecaptcha?.enterprise?.execute },
  }));
});

// content.js re-dispatches GET_CAPTCHA until it hears back (this script may
// not have loaded yet on the first dispatch), so ignore repeats for a request
// that is already being solved.
const _captchaInFlight = new Set();

window.addEventListener('GET_CAPTCHA', async ({ detail }) => {
  const { requestId, pageAction } = detail;
  if (_captchaInFlight.has(requestId)) return;
  _captchaInFlight.add(requestId);
  try {
    await waitForGrecaptcha();
    // execute() can hang indefinitely (e.g. while Google is throttling);
    // fail loudly instead of letting content.js report a bare CONTENT_TIMEOUT.
    const token = await Promise.race([
      window.grecaptcha.enterprise.execute(SITE_KEY, { action: pageAction }),
      new Promise((_, reject) => setTimeout(() => reject(new Error('grecaptcha execute timeout')), 15000)),
    ]);
    window.dispatchEvent(new CustomEvent('CAPTCHA_RESULT', {
      detail: { requestId, token },
    }));
  } catch (e) {
    window.dispatchEvent(new CustomEvent('CAPTCHA_RESULT', {
      detail: { requestId, error: e.message },
    }));
  } finally {
    _captchaInFlight.delete(requestId);
  }
});

function waitForGrecaptcha(timeout = 10000) {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    const check = () => {
      if (window.grecaptcha?.enterprise?.execute) return resolve();
      if (Date.now() - start > timeout) return reject(new Error('grecaptcha not available'));
      setTimeout(check, 200);
    };
    check();
  });
}

// ─── Video Upload Handler ───────────────────────────────────
window.addEventListener('UPLOAD_VIDEO', async ({ detail }) => {
  const { requestId, videoBase64, projectId } = detail;
  try {
    // Convert base64 to Blob
    const byteChars = atob(videoBase64);
    const byteArray = new Uint8Array(byteChars.length);
    for (let i = 0; i < byteChars.length; i++) {
      byteArray[i] = byteChars.charCodeAt(i);
    }
    const blob = new Blob([byteArray], { type: 'video/mp4' });

    // Step 1: POST start — get session URL
    const startResp = await _originalFetch('/fx/api/upload-video?action=start', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'X-Upload-Project-Id': projectId || '',
        'X-Upload-Content-Type': 'video/mp4',
        'X-Upload-Content-Length': blob.size.toString(),
      },
    });
    const sessionUrl = startResp.headers.get('X-Upload-Session-Url') || '';
    const startData = await startResp.json().catch(() => ({}));
    // sessionUrl may be in header OR in response body
    const finalSessionUrl = sessionUrl || startData.sessionUrl || '';
    startData._sessionUrl = finalSessionUrl;
    startData._status = startResp.status;

    if (!finalSessionUrl) {
      window.dispatchEvent(new CustomEvent('UPLOAD_VIDEO_RESULT', {
        detail: { requestId, error: 'NO_SESSION_URL', startData },
      }));
      return;
    }

    // Step 2: PUT directly to GCS session URL with resumable upload headers
    const uploadResp = await _originalFetch(finalSessionUrl, {
      method: 'PUT',
      body: blob,
      headers: {
        'Content-Type': 'video/mp4',
        'X-Goog-Upload-Command': 'upload, finalize',
        'X-Goog-Upload-Offset': '0',
      },
    });
    const uploadData = await uploadResp.json().catch(() => ({}));
    uploadData._status = uploadResp.status;

    window.dispatchEvent(new CustomEvent('UPLOAD_VIDEO_RESULT', {
      detail: { requestId, startData, uploadData, status: uploadResp.status },
    }));
  } catch (e) {
    window.dispatchEvent(new CustomEvent('UPLOAD_VIDEO_RESULT', {
      detail: { requestId, error: e.message },
    }));
  }
});
})();
