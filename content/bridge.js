// API Extraction Engine — Content Script Bridge (Isolated World)
// Bridges MAIN-world hooks/analyzer ↔ background service worker.
// Uses a random per-session channel set to prevent trivial interception by
// hostile page code: the MAIN world announces its channel via AGE_INIT and
// the bridge validates all subsequent messages against that set.
//
// NOTE: Service-worker intercepted fetch events (respondWith()) cannot be
// hooked from the page-world or isolated-world context. If a SW is installed
// on the target origin and intercepts requests before they hit the network,
// those requests will NOT appear in AGE captures. This is a browser-enforced
// limitation. Mitigation: install the extension before the target SW is
// activated, or use DevTools → Application → Service Workers → Bypass for
// network to force requests to reach the network layer where they can be
// observed.

(function () {
  'use strict';

  // Set of MAIN-world channels that have completed handshake with this bridge
  const _acceptedChannels = new Set();

  // ── Listen for messages from MAIN world (hooks.js, analyzer.js) ───────────
  window.addEventListener('message', (event) => {
    if (event.source !== window) return;
    const msg = event.data;
    if (!msg || typeof msg !== 'object' || typeof msg.type !== 'string') return;

    // Handshake: MAIN world announces its randomly-generated channel
    if (msg.type === 'AGE_INIT' && typeof msg.channel === 'string') {
      _acceptedChannels.add(msg.channel);
      // Acknowledge — MAIN world waits for this before sending captures
      window.postMessage({ type: 'AGE_INIT_ACK' }, '*');
      return;
    }

    // All other messages must carry a channel we've accepted
    if (!msg.channel || !_acceptedChannels.has(msg.channel)) return;

    // Forward to background, stripping the postMessage channel field
    _toBackground(msg);
  });

  // ── Forward a message to the background service worker ───────────────────
  function _toBackground(msg) {
    const { channel, ...fwd } = msg; // strip channel; keep type, id, payload

    // Map internal type names to SW router types
    const swMsg = _remap(fwd);

    chrome.runtime.sendMessage(swMsg, (response) => {
      if (chrome.runtime.lastError) {
        // SW may have gone idle; schedule a single retry
        setTimeout(() => chrome.runtime.sendMessage(swMsg).catch(() => {}), 150);
        return;
      }
      // If the MAIN world registered a response listener, forward it
      if (response !== undefined && msg.id !== undefined) {
        window.postMessage({
          type:     'AGE_RESPONSE',
          channel:  msg.channel,
          id:       msg.id,
          response,
        }, '*');
      }
    });
  }

  // Map from hooks/analyzer internal type names to SW router types
  function _remap(msg) {
    const map = {
      CAPTURE:        { type: 'CAPTURE',         payload: msg.payload },
      ANALYSIS_RESULT:{ type: 'ANALYSIS_RESULT', payload: msg.payload },
      STORAGE_SCAN:   { type: 'STORAGE_SCAN',    payload: msg.payload },
    };
    return map[msg.type] || msg;
  }

  // ── Trigger storage scan on DOMContentLoaded ─────────────────────────────
  // The isolated world has reliable access to document lifecycle events even
  // on pages with strict CSP. We tell MAIN world to run its storage scan.
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', _triggerStorageScan);
  } else {
    setTimeout(_triggerStorageScan, 50);
  }

  function _triggerStorageScan() {
    window.postMessage({ type: 'AGE_TRIGGER_STORAGE_SCAN' }, '*');
  }

  // ── SPA navigation detection ─────────────────────────────────────────────
  let _lastURL = location.href;
  const _navObserver = new MutationObserver(() => {
    if (location.href !== _lastURL) {
      _lastURL = location.href;
      window.postMessage({ type: 'AGE_NAVIGATION', url: _lastURL }, '*');
    }
  });
  _navObserver.observe(document.documentElement || document, {
    childList: true,
    subtree:   true,
  });

})();
