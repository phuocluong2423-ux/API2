// API Extraction Engine — Static Source Analyzer (MAIN World, document_idle)
// Scans every script tag, source map, storage surface, and window global
// for candidate API endpoints and GraphQL operations.
// Results are forwarded to the background via the same bridge used by hooks.js.

(function (globalThis) {
  'use strict';

  // ── Channel establishment ─────────────────────────────────────────────────
  const CHANNEL = 'AGE_ANALYZER_' + _rand();
  let   _ack    = false;
  let   _msgId  = 0;

  function _rand() {
    return Array.from(globalThis.crypto.getRandomValues(new Uint8Array(8)))
      .map(b => b.toString(16).padStart(2,'0')).join('');
  }

  globalThis.postMessage({ type: 'AGE_INIT', channel: CHANNEL }, '*');

  globalThis.addEventListener('message', ev => {
    if (ev.source !== globalThis) return;
    const d = ev.data;
    if (!d || typeof d !== 'object') return;
    if (d.type === 'AGE_INIT_ACK') _ack = true;
    if (d.type === 'AGE_TRIGGER_STORAGE_SCAN') _doStorageScan();
    if (d.type === 'AGE_NAVIGATION') setTimeout(_runAnalysis, 800);
  });

  function _post(type, payload) {
    globalThis.postMessage({ type, channel: CHANNEL, id: ++_msgId, payload }, '*');
  }

  // ── URL / Path Extraction ─────────────────────────────────────────────────

  function _extractURLs(text) {
    if (!text || typeof text !== 'string') return [];
    const seen    = new Set();
    const results = [];
    const add     = (url, type) => {
      url = url.replace(/[,;.'")\]}>]+$/, '');
      if (!seen.has(url) && url.length > 2 && url.length < 2048) {
        seen.add(url); results.push({ url, type });
      }
    };

    // Absolute URLs
    for (const m of text.matchAll(/https?:\/\/[^\s"'<>`\])}\\,;]{4,}/g)) add(m[0], 'absolute');

    // Path literals near HTTP/API keywords
    for (const m of text.matchAll(
      /(?:fetch|axios|got|request|http(?:Client|Service|s)?|url|endpoint|api|graphql|baseURL?|route|path|href)\s*[=:(,+<{]\s*['"`]?(\/[A-Za-z0-9_\-./{}\[\]:?=&%#@!$*+~]{2,512})/gi
    )) add(m[1], 'path_literal');

    // Route-map object keys: { "/api/...": ... }
    for (const m of text.matchAll(
      /['"](\/(api|v\d+|graphql|rest|rpc|service|data|auth|user|admin|internal|mobile|ws)[^'"]{1,400})['"]\s*:/g
    )) add(m[1], 'route_key');

    // Versioned prefixes
    for (const m of text.matchAll(
      /['"`](\/(?:v\d+|beta|internal|preview|staging|alpha|canary)\/[^'"` \t\n]{2,200})['"`]/g
    )) add(m[1], 'versioned');

    return results;
  }

  function _extractGQL(text) {
    if (!text) return [];
    const ops = [];

    // Named operations
    for (const m of text.matchAll(/(query|mutation|subscription)\s+(\w+)\s*(?:\([^)]{0,500}\))?\s*\{/g)) {
      const start = m.index;
      let depth = 0, i = start, lim = Math.min(text.length, start + 8000);
      while (i < lim) {
        if (text[i] === '{') depth++;
        else if (text[i] === '}') { depth--; if (depth === 0) break; }
        i++;
      }
      ops.push({ type: m[1], name: m[2], source: text.slice(start, Math.min(i+1, start+3000)) });
    }

    // gql`` tagged templates
    for (const m of text.matchAll(/gql`([\s\S]{4,3000}?)`/g)) {
      const src = m[1].trim();
      const tm  = src.match(/^(query|mutation|subscription)/);
      ops.push({ type: tm ? tm[1] : 'fragment', name: 'anonymous', source: src.slice(0,2000) });
    }

    return ops;
  }

  function _extractForeignHosts(text, pageHost) {
    const hosts = new Set();
    for (const m of text.matchAll(
      /['"`]https?:\/\/([a-zA-Z0-9](?:[a-zA-Z0-9\-.]*[a-zA-Z0-9])?(?::\d+)?)/g
    )) {
      const h = m[1].toLowerCase();
      if (h !== pageHost && h.includes('.') && h.length < 253 && !h.endsWith('.example.com'))
        hosts.add(h);
    }
    return Array.from(hosts);
  }

  // ── Script Fetching ───────────────────────────────────────────────────────

  async function _fetchText(url) {
    try {
      const res = await fetch(url, { credentials: 'omit', cache: 'force-cache' });
      if (!res.ok) return null;
      return await res.text();
    } catch { return null; }
  }

  async function _fetchSourceMap(scriptURL, scriptText) {
    const match = scriptText.match(/\/\/[#@]\s*sourceMappingURL=([^\s]+)/);
    if (!match) return null;

    const smRef = match[1];

    if (smRef.startsWith('data:')) {
      try {
        const b64 = smRef.split(',')[1];
        return JSON.parse(atob(b64));
      } catch { return null; }
    }

    try {
      const mapURL = new URL(smRef, scriptURL).href;
      const res    = await fetch(mapURL, { credentials: 'omit', cache: 'force-cache' });
      if (!res.ok) return null;
      return await res.json();
    } catch { return null; }
  }

  // ── Analysis of a Single Source ───────────────────────────────────────────

  async function _analyzeText(src, text, pageHost) {
    const endpoints = [];
    const gqlOps   = [];

    for (const item of _extractURLs(text)) {
      let host = pageHost;
      try { if (item.url.startsWith('http')) host = new URL(item.url).hostname; } catch {}
      endpoints.push({ ...item, source: src, host });
    }

    for (const host of _extractForeignHosts(text, pageHost)) {
      endpoints.push({ url: `https://${host}`, type: 'hostname', source: src, host });
    }

    gqlOps.push(..._extractGQL(text));

    return { endpoints, gqlOps };
  }

  // ── Storage / Window Global Scan ──────────────────────────────────────────

  function _doStorageScan() {
    const ls  = {};
    const ss  = {};
    const wg  = {};

    try {
      for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i);
        ls[k]   = localStorage.getItem(k);
      }
    } catch {}

    try {
      for (let i = 0; i < sessionStorage.length; i++) {
        const k = sessionStorage.key(i);
        ss[k]   = sessionStorage.getItem(k);
      }
    } catch {}

    // Well-known window globals
    const STATE_KEYS = [
      '__NEXT_DATA__','__NUXT__','__APOLLO_STATE__','__REDUX_STATE__',
      '__INITIAL_STATE__','__PRELOADED_STATE__','__APP_STATE__','__STORE__',
      '__ENV__','ENV','_env','CONFIG','__config','__settings',
      '__REACT_QUERY_STATE__','__SWR_CACHE__','appConfig','apiConfig',
    ];

    for (const k of STATE_KEYS) {
      try {
        if (globalThis[k] !== undefined) {
          wg[k] = typeof globalThis[k] === 'object'
            ? JSON.stringify(globalThis[k]).slice(0, 100000)
            : String(globalThis[k]).slice(0, 10000);
        }
      } catch {}
    }

    // Scan window.* for api|config|env|endpoints|settings objects
    for (const k of Object.getOwnPropertyNames(globalThis)) {
      if (/^(api|config|env|endpoints?|settings|app|_routes?|routes?)$/i.test(k)) {
        try {
          const v = globalThis[k];
          if (v && typeof v === 'object' && !Array.isArray(v))
            wg[k] = JSON.stringify(v).slice(0, 100000);
        } catch {}
      }
    }

    _post('STORAGE_SCAN', { localStorage: ls, sessionStorage: ss, windowGlobals: wg });
  }

  // ── Meta Tags and HTML Comments ───────────────────────────────────────────

  function _scanDOM(pageHost) {
    const endpoints = [];

    // Meta tags
    document.querySelectorAll('meta[content]').forEach(meta => {
      const content = meta.getAttribute('content') || '';
      const name    = meta.getAttribute('name') || meta.getAttribute('property') || '';
      if (/https?:|\/api\/|\/graphql/.test(content)) {
        endpoints.push({ url: content, source: `meta:${name}`, type: 'meta', host: pageHost });
      }
    });

    // Preload / prefetch link tags that hint at API resources
    document.querySelectorAll('link[rel][href]').forEach(link => {
      const href = link.getAttribute('href') || '';
      if (/\/api\/|\/graphql|\.json/.test(href))
        endpoints.push({ url: href, source: 'link_hint', type: 'link', host: pageHost });
    });

    // HTML comments
    const walker = document.createTreeWalker(document, NodeFilter.SHOW_COMMENT, null);
    let node;
    while ((node = walker.nextNode())) {
      const text = node.textContent || '';
      if (text.length > 8 && text.length < 8000) {
        for (const item of _extractURLs(text))
          endpoints.push({ ...item, source: 'html_comment', host: pageHost });
      }
    }

    return endpoints;
  }

  // ── Cache Storage Manifest ─────────────────────────────────────────────────

  async function _scanCacheStorage(pageHost) {
    const endpoints = [];
    try {
      const cacheNames = await caches.keys();
      for (const name of cacheNames) {
        const cache   = await caches.open(name);
        const keys    = await cache.keys();
        for (const req of keys) {
          endpoints.push({ url: req.url, source: `cache:${name}`, type: 'cache', host: pageHost });
        }
      }
    } catch { /* caches API may not be available */ }
    return endpoints;
  }

  // ── Main Analysis Routine ─────────────────────────────────────────────────

  async function _runAnalysis() {
    const pageHost    = location.hostname;
    const allEndpoints = [];
    const allGQL      = [];

    // 1. Script elements
    const scripts  = Array.from(document.querySelectorAll('script'));
    const promises = scripts.map(async (script) => {
      if (script.src) {
        const text = await _fetchText(script.src);
        if (!text) return;
        const { endpoints, gqlOps } = await _analyzeText(script.src, text, pageHost);
        allEndpoints.push(...endpoints);
        allGQL.push(...gqlOps);

        // Source map
        const sm = await _fetchSourceMap(script.src, text);
        if (sm) {
          // Paths listed in sources[]
          for (const s of (sm.sources || [])) {
            if (s && s.length < 2048)
              allEndpoints.push({ url: s, type: 'sourcemap', source: script.src, host: pageHost });
          }
          // Actual source content
          for (const content of (sm.sourcesContent || [])) {
            if (content) {
              const r = await _analyzeText(script.src + '[map]', content, pageHost);
              allEndpoints.push(...r.endpoints);
              allGQL.push(...r.gqlOps);
            }
          }
        }
      } else if (script.textContent && script.textContent.trim().length > 0) {
        const { endpoints, gqlOps } = await _analyzeText('inline://' + pageHost, script.textContent, pageHost);
        allEndpoints.push(...endpoints);
        allGQL.push(...gqlOps);
      }
    });

    await Promise.allSettled(promises);

    // 2. DOM scan
    allEndpoints.push(..._scanDOM(pageHost));

    // 3. Cache Storage
    allEndpoints.push(...await _scanCacheStorage(pageHost));

    // 4. Storage values — scan for embedded URLs
    const wg = {};
    const STATE_KEYS = [
      '__NEXT_DATA__','__NUXT__','__APOLLO_STATE__','__REDUX_STATE__',
      '__INITIAL_STATE__','__PRELOADED_STATE__',
    ];
    for (const k of STATE_KEYS) {
      try {
        if (globalThis[k]) wg[k] = JSON.stringify(globalThis[k]).slice(0, 100000);
      } catch {}
    }
    for (const [, val] of Object.entries(wg)) {
      for (const item of _extractURLs(val))
        allEndpoints.push({ ...item, source: 'window_global', host: pageHost });
      allGQL.push(..._extractGQL(val));
    }

    // 5. Deduplicate
    const seen     = new Set();
    const unique   = allEndpoints.filter(ep => {
      if (seen.has(ep.url)) return false;
      seen.add(ep.url);
      return true;
    });

    // 6. Filter noise
    const filtered = unique.filter(ep => {
      const u = ep.url;
      if (u.length < 3) return false;
      if (/\.(css|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|mp4|webm|pdf|map|txt\.gz)(\?|$)/i.test(u)) return false;
      if (u.startsWith('data:')) return false;
      if (u.startsWith('blob:')) return false;
      if (/^(tel|mailto|javascript):/.test(u)) return false;
      return true;
    });

    // 7. Send to background
    _post('ANALYSIS_RESULT', {
      host:       pageHost,
      endpoints:  filtered.slice(0, 2000),
      graphqlOps: allGQL.slice(0, 500),
      timestamp:  Date.now(),
    });

    console.debug(`[AGE Analyzer] ${filtered.length} endpoints, ${allGQL.length} GQL ops on ${pageHost}`);
  }

  // ── Bootstrap ─────────────────────────────────────────────────────────────

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => setTimeout(_runAnalysis, 300));
  } else {
    setTimeout(_runAnalysis, 300);
  }

})(typeof globalThis !== 'undefined' ? globalThis : window);
