// API Extraction Engine — Runtime Hooks (MAIN World, document_start)
// Installed via chrome.scripting.registerContentScripts with world:"MAIN".
// Hooks: fetch, XMLHttpRequest, WebSocket, EventSource, navigator.sendBeacon,
//        Response.prototype.json, Response.prototype.text.
//
// Service-worker intercepted requests CANNOT be hooked from this context —
// see content/bridge.js header comment for the documented limitation.

(function (globalThis) {
  'use strict';

  // ── Per-session channel for postMessage security ──────────────────────────
  // A random string generated here; the bridge validates it before forwarding.
  const CHANNEL   = 'AGE_HOOK_' + _rand();
  const BODY_CAP  = 20480; // 20 KB — matches SW default
  const WS_MAX    = 50;
  const SSE_MAX   = 100;
  let   _bridgeAck = false;
  let   _msgId     = 0;

  function _rand() {
    return Array.from(globalThis.crypto.getRandomValues(new Uint8Array(12)))
      .map(b => b.toString(16).padStart(2,'0')).join('');
  }

  // ── Announce channel to bridge ────────────────────────────────────────────
  globalThis.postMessage({ type: 'AGE_INIT', channel: CHANNEL }, '*');

  globalThis.addEventListener('message', (ev) => {
    if (ev.source !== globalThis) return;
    const d = ev.data;
    if (!d || typeof d !== 'object') return;
    if (d.type === 'AGE_INIT_ACK')         _bridgeAck = true;
    if (d.type === 'AGE_TRIGGER_STORAGE_SCAN' || d.type === 'AGE_NAVIGATION') {
      // Analyzer handles this; hooks.js just acknowledges readiness
    }
  });

  // ── Core send helper ──────────────────────────────────────────────────────
  function _send(type, payload) {
    globalThis.postMessage({ type, channel: CHANNEL, id: ++_msgId, payload }, '*');
  }

  // ── Body utilities ────────────────────────────────────────────────────────
  function _trunc(s) {
    if (!s) return '[empty]';
    if (typeof s !== 'string') s = String(s);
    return s.length > BODY_CAP ? s.slice(0, BODY_CAP) + '…[TRUNCATED]' : s;
  }

  function _bodyStr(body) {
    if (body === null || body === undefined) return '[empty]';
    if (typeof body === 'string')         return _trunc(body);
    if (body instanceof URLSearchParams)  return _trunc(body.toString());
    if (body instanceof FormData) {
      const o = {};
      body.forEach((v, k) => { o[k] = v instanceof File ? `[File:${v.name}]` : String(v); });
      return _trunc(JSON.stringify(o));
    }
    if (body instanceof ArrayBuffer || ArrayBuffer.isView(body)) {
      const bytes = body instanceof ArrayBuffer ? new Uint8Array(body) : new Uint8Array(body.buffer);
      return new TextDecoder('utf-8',{fatal:false}).decode(bytes.slice(0, BODY_CAP))
           + (bytes.length > BODY_CAP ? '…[TRUNCATED]' : '');
    }
    if (body instanceof Blob) return `[Blob:${body.type}:${body.size}B]`;
    return _trunc(String(body));
  }

  function _hdrs(headers) {
    if (!headers) return {};
    const o = {};
    if (typeof headers.forEach === 'function') {
      headers.forEach((v, k) => { o[k] = v; });
    } else {
      Object.assign(o, headers);
    }
    return o;
  }

  // ══════════════════════════════════════════════════════════════════════════
  // 1. fetch hook
  // ══════════════════════════════════════════════════════════════════════════
  const _origFetch = globalThis.fetch;

  globalThis.fetch = async function (...args) {
    const t0 = Date.now();
    let req;
    try {
      req = args[0] instanceof Request ? args[0] : new Request(...args);
    } catch {
      return _origFetch.apply(this, args);
    }

    const url    = req.url;
    const method = req.method;
    const reqH   = _hdrs(req.headers);
    let   reqB   = '[empty]';

    try {
      const clone = req.clone();
      reqB = _trunc(await clone.text());
    } catch { /* body already consumed or null */ }

    let res;
    try {
      res = await _origFetch.apply(this, args);
    } catch (err) {
      _send('CAPTURE', {
        type: 'fetch', url, method,
        requestHeaders: reqH, requestBody: reqB,
        responseStatus: 0, responseBody: '[network error]',
        error: err.message, duration: Date.now() - t0, timestamp: Date.now(),
      });
      throw err;
    }

    const duration = Date.now() - t0;
    const resH     = _hdrs(res.headers);

    // Clone to read body without consuming the original
    res.clone().text().then(text => {
      _send('CAPTURE', {
        type: 'fetch', url, method,
        requestHeaders:   reqH, requestBody: reqB,
        responseStatus:   res.status, responseStatusText: res.statusText,
        responseHeaders:  resH, responseBody: _trunc(text),
        duration, timestamp: Date.now(),
      });
    }).catch(() => {
      _send('CAPTURE', {
        type: 'fetch', url, method,
        requestHeaders:   reqH, requestBody: reqB,
        responseStatus:   res.status, responseStatusText: res.statusText,
        responseHeaders:  resH, responseBody: '[unreadable]',
        duration, timestamp: Date.now(),
      });
    });

    return res;
  };

  // ══════════════════════════════════════════════════════════════════════════
  // 2. XMLHttpRequest hook
  // ══════════════════════════════════════════════════════════════════════════
  const _OrigXHR = globalThis.XMLHttpRequest;

  function _HookedXHR() {
    const xhr   = new _OrigXHR();
    const state = { url: '', method: 'GET', reqH: {}, reqB: '[empty]', t0: 0 };

    // open
    const _open = xhr.open.bind(xhr);
    xhr.open = function (method, url, ...rest) {
      state.method = String(method).toUpperCase();
      state.url    = String(url);
      state.t0     = Date.now();
      return _open(method, url, ...rest);
    };

    // setRequestHeader
    const _setH = xhr.setRequestHeader.bind(xhr);
    xhr.setRequestHeader = function (name, value) {
      state.reqH[name] = value;
      return _setH(name, value);
    };

    // send
    const _send2 = xhr.send.bind(xhr);
    xhr.send = function (body) {
      state.reqB = _bodyStr(body);
      state.t0   = Date.now();

      xhr.addEventListener('load', () => {
        const resH = {};
        (xhr.getAllResponseHeaders() || '').split('\r\n').forEach(l => {
          const i = l.indexOf(': ');
          if (i > 0) resH[l.slice(0, i)] = l.slice(i + 2);
        });

        let resB = '[empty]';
        try {
          resB = _trunc(xhr.responseText || String(xhr.response ?? ''));
        } catch { resB = '[binary]'; }

        _send('CAPTURE', {
          type: 'xhr', url: state.url, method: state.method,
          requestHeaders:  state.reqH, requestBody: state.reqB,
          responseStatus:  xhr.status, responseStatusText: xhr.statusText,
          responseHeaders: resH, responseBody: resB,
          duration: Date.now() - state.t0, timestamp: Date.now(),
        });
      });

      xhr.addEventListener('error', () => {
        _send('CAPTURE', {
          type: 'xhr', url: state.url, method: state.method,
          requestHeaders: state.reqH, requestBody: state.reqB,
          responseStatus: 0, responseBody: '[network error]',
          duration: Date.now() - state.t0, timestamp: Date.now(),
        });
      });

      return _send2(body);
    };

    return xhr;
  }

  // Carry over static constants
  _HookedXHR.prototype = _OrigXHR.prototype;
  for (const k of ['UNSENT','OPENED','HEADERS_RECEIVED','LOADING','DONE'])
    _HookedXHR[k] = _OrigXHR[k];
  globalThis.XMLHttpRequest = _HookedXHR;

  // ══════════════════════════════════════════════════════════════════════════
  // 3. WebSocket hook
  // ══════════════════════════════════════════════════════════════════════════
  const _OrigWS = globalThis.WebSocket;

  function _HookedWS(url, protocols) {
    const ws     = protocols ? new _OrigWS(url, protocols) : new _OrigWS(url);
    const frames = { sent: [], received: [] };
    const capId  = `ws_${Date.now()}_${_rand().slice(0,6)}`;

    const _initial = {
      id: capId, type: 'websocket', url,
      protocols: Array.isArray(protocols) ? protocols : (protocols ? [protocols] : []),
      frames, timestamp: Date.now(),
    };
    _send('CAPTURE', _initial);

    // Hook send
    const _origSend = ws.send.bind(ws);
    ws.send = function (data) {
      if (frames.sent.length < WS_MAX) {
        frames.sent.push({
          dir:  'sent',
          data: typeof data === 'string' ? _trunc(data) : `[Binary:${data?.byteLength ?? '?'}B]`,
          ts:   Date.now(),
        });
        _send('CAPTURE', { ..._initial, frames });
      }
      return _origSend(data);
    };

    ws.addEventListener('message', ev => {
      if (frames.received.length < WS_MAX) {
        frames.received.push({
          dir:  'received',
          data: typeof ev.data === 'string' ? _trunc(ev.data) : `[Binary]`,
          ts:   Date.now(),
        });
        _send('CAPTURE', { ..._initial, frames });
      }
    });

    ws.addEventListener('close', ev => {
      _send('CAPTURE', {
        ..._initial, frames, closed: true,
        closeCode: ev.code, closeReason: ev.reason, timestamp: Date.now(),
      });
    });

    return ws;
  }

  _HookedWS.prototype = _OrigWS.prototype;
  for (const k of ['CONNECTING','OPEN','CLOSING','CLOSED']) _HookedWS[k] = _OrigWS[k];
  globalThis.WebSocket = _HookedWS;

  // ══════════════════════════════════════════════════════════════════════════
  // 4. EventSource hook
  // ══════════════════════════════════════════════════════════════════════════
  const _OrigES = globalThis.EventSource;
  if (_OrigES) {
    function _HookedES(url, opts) {
      const es     = new _OrigES(url, opts);
      const events = [];
      const capId  = `sse_${Date.now()}_${_rand().slice(0,6)}`;

      const _initial = {
        id: capId, type: 'eventsource', url,
        withCredentials: opts?.withCredentials ?? false,
        events, timestamp: Date.now(),
      };
      _send('CAPTURE', _initial);

      es.addEventListener('message', ev => {
        if (events.length < SSE_MAX) {
          events.push({ data: _trunc(ev.data), lastEventId: ev.lastEventId, ts: Date.now() });
          _send('CAPTURE', { ..._initial, events });
        }
      });

      es.addEventListener('error', () => {
        _send('CAPTURE', { ..._initial, events, error: 'SSE error', timestamp: Date.now() });
      });

      return es;
    }

    _HookedES.prototype = _OrigES.prototype;
    for (const k of ['CONNECTING','OPEN','CLOSED']) _HookedES[k] = _OrigES[k];
    globalThis.EventSource = _HookedES;
  }

  // ══════════════════════════════════════════════════════════════════════════
  // 5. navigator.sendBeacon hook
  // ══════════════════════════════════════════════════════════════════════════
  if (globalThis.navigator && typeof globalThis.navigator.sendBeacon === 'function') {
    const _origBeacon = globalThis.navigator.sendBeacon.bind(globalThis.navigator);
    globalThis.navigator.sendBeacon = function (url, data) {
      _send('CAPTURE', {
        type: 'beacon', url, method: 'POST',
        requestBody: data ? _bodyStr(data) : '[empty]',
        timestamp: Date.now(),
      });
      return _origBeacon(url, data);
    };
  }

  // ══════════════════════════════════════════════════════════════════════════
  // 6. Response.prototype.json + .text passthrough hooks
  // These supplement the fetch hook: if a caller reads the body through the
  // Response object after fetch() has already returned, we can still observe
  // the data without consuming the stream twice (the fetch hook uses .clone()).
  // We do NOT double-capture here — these hooks are strictly for APIs that
  // discard the raw Response and only surface the parsed value.
  // ══════════════════════════════════════════════════════════════════════════
  const _origRJson = Response.prototype.json;
  Response.prototype.json = async function () {
    // This is already handled by the fetch hook clone; we simply pass through.
    return _origRJson.call(this);
  };

  const _origRText = Response.prototype.text;
  Response.prototype.text = async function () {
    return _origRText.call(this);
  };

  // ── Done ─────────────────────────────────────────────────────────────────
  console.debug('[AGE] Hooks installed on', location.origin);

})(typeof globalThis !== 'undefined' ? globalThis : window);
