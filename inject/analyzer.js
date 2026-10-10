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

  // Keep analysis bounded so large sites do not overwhelm the browser.
  const MAX_SCRIPT_SOURCES = 100;
  const MAX_SOURCE_BYTES = 1024 * 1024;
  const MAX_SOURCE_MAP_BYTES = 3 * 1024 * 1024;
  const MAX_TOTAL_SOURCE_CHARS = 8 * 1024 * 1024;
  let _scannedExternalSources = new Set();
  let _analysisTimer = null;
  let _analysisRunning = false;
  let _analysisPending = false;
  let _autoRescans = 0;

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
    if (d.type === 'AGE_NAVIGATION') _scheduleAnalysis(800, true);
  });

  function _post(type, payload) {
    globalThis.postMessage({ type, channel: CHANNEL, id: ++_msgId, payload }, '*');
  }

  // ── URL / Path Extraction ─────────────────────────────────────────────────

  function _extractURLs(text) {
    if (!text || typeof text !== 'string') return [];
    const seen = new Set();
    const results = [];
    // Many bundles escape URL separators inside JSON strings and generated code.
    // Analyze both the original source and a conservative decoded view.
    const decodedText = text
      .replace(/\\u002f/gi, '/')
      .replace(/\\x2f/gi, '/')
      .replace(/\\\//g, '/')
      .replace(/\\u003a/gi, ':')
      .replace(/\\x3a/gi, ':');
    const scanTexts = decodedText === text ? [text] : [text, decodedText];
    const apiPath = /\/(?:api|_api|webapi|v\d+|graphql|gql|trpc|rpc|rest|service|data|auth|oauth|session|admin|internal|mobile|gateway|query|mutation|ajax|backend|functions|\.well-known)(?:\/|[?#]|$)/i;
    const add = (raw, type) => {
      const url = String(raw || '').replace(/[,;.'")\]}>]+$/, '');
      if (url.length < 3 || url.length >= 2048 || seen.has(url)) return;
      if (/^(?:javascript|data|blob|mailto|tel):/i.test(url)) return;
      seen.add(url);
      let confidence = 45;
      if (type === 'absolute') {
        try { confidence = apiPath.test(new URL(url).pathname) ? 88 : 58; } catch {}
      } else if (type === 'path_literal') confidence = 82;
      else if (type === 'route_key') confidence = 79;
      else if (type === 'versioned') confidence = 74;
      else if (type === 'api_path') confidence = 76;
      else if (type === 'base_url') confidence = 70;
      else if (type === 'request_call') confidence = 84;
      else if (type === 'framework_route') confidence = 86;
      results.push({ url, type, confidence, evidence: type });
    };

    for (const sourceText of scanTexts) {
      // Absolute URL literals.
      for (const m of sourceText.matchAll(/https?:\/\/[^\s"'<>\x60\])}\\,;]{4,}/g)) add(m[0], 'absolute');

      // Common request call sites, including client.get('/resource') and fetch('/resource').
      for (const m of sourceText.matchAll(/\b(?:fetch|open|request|get|post|put|patch|delete|head|options|query|mutate)\s*\(\s*['"\x60]((?:https?:\/\/|\/)[A-Za-z0-9_\-./{}\[\]:?=&%#@!$*+~]{1,900})['"\x60]/gi)) {
        add(m[1], 'request_call');
      }

      // Framework/router declarations such as router.get('/users') and app.use('/api').
      for (const m of sourceText.matchAll(/\b(?:router|app|server|route|fastify|express|apiRouter)\s*\.\s*(?:get|post|put|patch|delete|options|head|all|use|route)\s*\(\s*['"\x60](\/[^'"\x60\s]{1,900})['"\x60]/gi)) {
        add(m[1], 'framework_route');
      }

      // Framework decorators such as @Get('users') / @Controller('api/v1').
      for (const m of sourceText.matchAll(/@(Get|Post|Put|Patch|Delete|Options|Head|All|Controller)\s*\(\s*['"\x60]([^'"\x60\s]{1,500})['"\x60]\s*\)/g)) {
        const path = m[2].startsWith('/') ? m[2] : '/' + m[2];
        add(path, 'framework_route');
      }

      // URL/path-like values attached to meaningful configuration keys.
      for (const m of sourceText.matchAll(/(?:fetch|axios|got|request|http(?:Client|Service|s)?|url|endpoint|api|graphql|baseURL?|apiBaseURL|apiUrl|route|path|href|uri|resource)\s*[=:(,+<{]\s*['"\x60]?((?:https?:\/\/|\/)\/*[A-Za-z0-9_\-./{}\[\]:?=&%#@!$*+~]{1,1024})/gi)) {
        add(m[1], m[1].startsWith('/') ? 'path_literal' : 'absolute');
      }

      // Conventional API roots, including GraphQL, RPC and versioned endpoints.
      for (const m of sourceText.matchAll(/['"\x60]((?:\/(?:api|_api|webapi|v\d+|graphql|gql|trpc|rpc|rest|service|data|auth|oauth|session|admin|internal|mobile|gateway|query|mutation|ajax|backend|functions|\.well-known)(?:\/[^'"\x60\s]{0,400})?))['"\x60]/gi)) {
        add(m[1], 'api_path');
      }

      for (const m of sourceText.matchAll(/['"]((?:\/(?:api|v\d+|graphql|gql|trpc|rpc|rest|service|data|auth|admin|internal|mobile|gateway)[^'"]{1,400}))['"]\s*:/gi)) add(m[1], 'route_key');
      for (const m of sourceText.matchAll(/['"\x60](\/(?:v\d+|beta|internal|preview|staging|alpha|canary)\/[^'"\x60\s]{2,200})['"\x60]/g)) add(m[1], 'versioned');
      for (const m of sourceText.matchAll(/(?:apiBaseUrl|apiBaseURL|baseURL|graphqlEndpoint|apiEndpoint)\s*[:=]\s*['"\x60](https?:\/\/[^'"\x60\s]{4,500}|\/[^'"\x60\s]{2,300})['"\x60]/gi)) add(m[1], 'base_url');
    }
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

  // Read at most maxBytes from an already-loaded script/source-map URL.
  // This prevents a very large bundle from consuming unbounded memory.
  async function _fetchText(url, maxBytes = MAX_SOURCE_BYTES) {
    try {
      const res = await fetch(url, { credentials: 'omit', cache: 'force-cache' });
      if (!res.ok) return null;
      const declared = Number(res.headers.get('content-length') || 0);
      if (declared > maxBytes * 20) return null;
      if (!res.body || !res.body.getReader) {
        const text = await res.text();
        return text.length > maxBytes ? text.slice(0, maxBytes) : text;
      }
      const reader = res.body.getReader();
      const chunks = [];
      let size = 0;
      while (size < maxBytes) {
        const part = await reader.read();
        if (part.done) break;
        const remaining = maxBytes - size;
        const chunk = part.value.byteLength > remaining
          ? part.value.slice(0, remaining) : part.value;
        chunks.push(chunk);
        size += chunk.byteLength;
        if (chunk.byteLength < part.value.byteLength) {
          await reader.cancel().catch(() => {});
          break;
        }
      }
      const bytes = new Uint8Array(size);
      let offset = 0;
      for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
      return new TextDecoder().decode(bytes);
    } catch { return null; }
  }

  async function _fetchSourceMap(scriptURL, scriptText) {
    const match = scriptText.match(/(?:\/\/|\/\*)[#@]\s*sourceMappingURL=([^\s*]+)/);
    if (!match) return null;

    const smRef = match[1];

    if (smRef.startsWith('data:')) {
      if (smRef.length > MAX_SOURCE_MAP_BYTES * 2) return null;
      try {
        const comma = smRef.indexOf(',');
        if (comma < 0) return null;
        const data = smRef.slice(comma + 1);
        const decoded = smRef.slice(0, comma).includes(';base64')
          ? atob(data) : decodeURIComponent(data);
        if (decoded.length > MAX_SOURCE_MAP_BYTES) return null;
        return JSON.parse(decoded);
      } catch { return null; }
    }

    try {
      const mapURL = new URL(smRef, scriptURL).href;
      const text = await _fetchText(mapURL, MAX_SOURCE_MAP_BYTES);
      if (!text || text.length >= MAX_SOURCE_MAP_BYTES) return null;
      return JSON.parse(text);
    } catch { return null; }
  }

  // ── Analysis of a Single Source ───────────────────────────────────────────

  async function _analyzeText(src, text, pageHost) {
    const endpoints = [];
    const gqlOps = [];
    for (const item of _extractURLs(text)) {
      let host = pageHost;
      try { if (/^https?:\/\//i.test(item.url)) host = new URL(item.url).hostname; } catch {}
      endpoints.push({ ...item, source: src, host, discoveryMethod: 'static_source', observed: false });
    }
    for (const host of _extractForeignHosts(text, pageHost)) {
      endpoints.push({ url: `https://${host}`, type: 'hostname', confidence: 35,
        evidence: 'foreign_hostname_literal', source: src, host, discoveryMethod: 'static_source', observed: false });
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

  // ── Runtime Resource Clues ────────────────────────────────────────────────

  function _scanPerformanceResources(pageHost) {
    const endpoints = [];
    try {
      const entries = performance.getEntriesByType('resource').slice(-1500);
      for (const entry of entries) {
        const url = String(entry.name || '');
        if (!/^https?:\/\//i.test(url)) continue;
        const initiator = String(entry.initiatorType || '').toLowerCase();
        const likelyAPI = /\/(?:api|_api|graphql|gql|trpc|rpc|rest|service|gateway|v\d+)(?:\/|[?#]|$)/i.test(url);
        if (!['fetch', 'xmlhttprequest'].includes(initiator) && !likelyAPI) continue;
        if (/\.(?:css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|mp4|webm|pdf)(?:[?#]|$)/i.test(url)) continue;
        let host = pageHost;
        try { host = new URL(url).hostname; } catch {}
        endpoints.push({
          url, host, source: 'performance:' + (initiator || 'resource'),
          type: 'runtime_resource', confidence: ['fetch','xmlhttprequest'].includes(initiator) ? 74 : 62,
          evidence: 'performance_resource_timing', discoveryMethod: 'runtime_resource', observed: true,
        });
      }
    } catch {}
    return endpoints;
  }

  function _normalizeEndpoint(item, pageHost) {
    const url = String(item?.url || '').trim();
    if (!url || url.length >= 2048 || /^(?:data|blob|javascript|mailto|tel):/i.test(url)) return null;
    let host = item.host || pageHost;
    try {
      const parsed = new URL(url, location.href);
      if (!['http:', 'https:'].includes(parsed.protocol)) return null;
      if (/^https?:\/\//i.test(url)) host = parsed.hostname;
    } catch {
      if (!url.startsWith('/')) return null;
    }
    const score = Number(item.confidence);
    const confidence = Number.isFinite(score) ? Math.max(0, Math.min(100, score)) : 45;
    return {
      ...item, url, host, confidence,
      confidenceLabel: confidence >= 80 ? 'high' : confidence >= 60 ? 'medium' : 'low',
      source: String(item.source || 'unknown').slice(0, 500),
      discoveryMethod: item.discoveryMethod || item.type || 'static_source',
      evidence: String(item.evidence || item.type || 'candidate').slice(0, 160),
      observed: item.observed === true,
    };
  }

  // ── Passive Deep Find: page inventory, technology clues, routes and security signals
  // Never collect form values or storage values here; only structure and field names.
  function _scanSiteProfile(pageHost) {
    const originURL = location.origin;
    const safeURL = (raw, keepOrigin = true) => {
      try {
        const u = new URL(raw, location.href);
        if (!['http:', 'https:'].includes(u.protocol)) return '';
        u.username = '';
        u.password = '';
        u.search = '';
        u.hash = '';
        return keepOrigin ? u.origin + u.pathname : u.pathname;
      } catch {
        return typeof raw === 'string' && raw.startsWith('/') ? raw.split(/[?#]/)[0].slice(0, 1024) : '';
      }
    };
    const uniqStrings = (values, cap = 100) => Array.from(new Set(values.filter(Boolean))).slice(0, cap);
    const getMeta = name => {
      const el = document.querySelector('meta[name="' + name.replace(/["\\]/g, '') + '"]');
      return String(el?.content || '').trim().slice(0, 300);
    };
    const assetList = (selector, attr, cap = 100) => {
      const values = [];
      for (const el of Array.from(document.querySelectorAll(selector)).slice(0, cap * 3)) {
        const raw = el.getAttribute(attr);
        const url = raw ? safeURL(raw, true) : '';
        if (url) values.push(url);
      }
      return uniqStrings(values, cap);
    };
    const pageURL = safeURL(location.href, true);
    const scripts = assetList('script[src]', 'src', 120);
    const styles = assetList('link[rel~="stylesheet"][href]', 'href', 100);
    const images = assetList('img[src],source[src]', 'src', 100);
    const frames = assetList('iframe[src]', 'src', 50);
    const manifests = assetList('link[rel="manifest"][href]', 'href', 10);
    const icons = assetList('link[rel~="icon"][href]', 'href', 20);
    const allResourceURLs = uniqStrings([
      ...scripts, ...styles, ...images, ...frames, ...manifests,
      ...Array.from(performance.getEntriesByType('resource').slice(-500), e => safeURL(e.name, true)),
    ], 500);
    const externalOrigins = uniqStrings(allResourceURLs.map(value => {
      try { const u = new URL(value); return u.origin !== originURL ? u.origin : ''; } catch { return ''; }
    }), 100);

    const technologies = [];
    const addTech = (name, evidence, confidence = 65) => {
      if (technologies.some(t => t.name === name)) return;
      technologies.push({ name, evidence: String(evidence).slice(0, 180), confidence });
    };
    const sourceHints = scripts.concat(styles).join('\n').toLowerCase();
    const htmlHints = (document.documentElement?.outerHTML || '').slice(0, 250000);
    if (/\/_next\/|__NEXT_DATA__/.test(sourceHints + htmlHints)) addTech('Next.js', 'Next.js asset path or page-state marker', 92);
    if (/\/_nuxt\/|__NUXT__/.test(sourceHints + htmlHints)) addTech('Nuxt', 'Nuxt asset path or page-state marker', 92);
    if (/ng-version=|angular\.js|angular\.min\.js/i.test(sourceHints + htmlHints)) addTech('Angular', 'Angular asset or ng-version marker', 88);
    if (/react(?:-dom)?(?:\.production)?(?:\.min)?\.js/i.test(sourceHints) || document.querySelector('[data-reactroot], #__next')) addTech('React', 'React bundle or DOM marker', 80);
    if (/vue(?:\.runtime)?(?:\.global)?(?:\.prod)?(?:\.min)?\.js/i.test(sourceHints) || document.querySelector('[data-v-app], [data-vue-meta]')) addTech('Vue.js', 'Vue bundle or DOM marker', 80);
    if (/\/_astro\/|astro-island/i.test(sourceHints + htmlHints)) addTech('Astro', 'Astro asset or island marker', 88);
    if (/\/_svelte\/|data-svelte-h/i.test(sourceHints + htmlHints)) addTech('Svelte', 'Svelte asset or DOM marker', 78);
    if (/\/wp-content\/|\/wp-includes\//i.test(sourceHints)) addTech('WordPress', 'WordPress asset path', 90);
    if (/cdn\.shopify\.com|shopify\.com\/s\/files/i.test(sourceHints)) addTech('Shopify', 'Shopify asset host', 88);
    if (/jquery(?:-\d+(?:\.\d+){0,2})?(?:\.min)?\.js/i.test(sourceHints)) addTech('jQuery', 'jQuery bundle filename', 82);
    if (/bootstrap(?:\.bundle)?(?:\.min)?\.js|bootstrap(?:\.min)?\.css/i.test(sourceHints)) addTech('Bootstrap', 'Bootstrap asset filename', 82);
    if (/\/assets\/index-[^/]+\.js|\/@vite\/client|vite\.svg/i.test(sourceHints)) addTech('Vite', 'Vite asset or development-client marker', 74);
    if (/webpackJsonp|webpackChunk|__webpack_require__/i.test(htmlHints)) addTech('Webpack', 'Webpack runtime marker', 78);
    if (/\/_gatsby\/|___gatsby/i.test(sourceHints + htmlHints)) addTech('Gatsby', 'Gatsby asset or DOM marker', 86);
    const generator = getMeta('generator');
    if (generator) addTech('Generator metadata', generator, 95);
    if (globalThis.jQuery || globalThis.$?.fn?.jquery) addTech('jQuery', 'jQuery runtime global', 90);
    if (globalThis.angular || document.documentElement?.hasAttribute('ng-version')) addTech('Angular', 'Angular runtime/DOM marker', 92);
    if (globalThis.Vue || document.querySelector('[data-v-app]')) addTech('Vue.js', 'Vue runtime/DOM marker', 88);
    if (globalThis.__NEXT_DATA__) addTech('Next.js', 'Next.js runtime state marker', 96);
    if (globalThis.__NUXT__) addTech('Nuxt', 'Nuxt runtime state marker', 96);

    const routes = [];
    const linkSeen = new Set();
    let externalLinkCount = 0;
    let newTabWithoutNoopener = 0;
    for (const a of Array.from(document.querySelectorAll('a[href]')).slice(0, 1000)) {
      const raw = a.getAttribute('href') || '';
      const url = safeURL(raw, true);
      if (!url) continue;
      try {
        const u = new URL(url);
        if (u.origin !== originURL) externalLinkCount++;
        else if (!linkSeen.has(u.pathname)) {
          linkSeen.add(u.pathname);
          routes.push(u.pathname.slice(0, 300));
        }
      } catch {}
      if (a.target === '_blank' && !/\bnoopener\b|\bnoreferrer\b/i.test(a.rel || '')) newTabWithoutNoopener++;
    }

    const forms = [];
    const securitySignals = [];
    const formElements = Array.from(document.querySelectorAll('form')).slice(0, 80);
    for (const form of formElements) {
      const rawAction = form.getAttribute('action') || location.href;
      const action = safeURL(rawAction, true) || pageURL;
      let actionOrigin = '';
      try { actionOrigin = new URL(action).origin; } catch {}
      const fields = Array.from(form.querySelectorAll('input,select,textarea,button')).slice(0, 40).map(field => ({
        name: String(field.getAttribute('name') || field.id || '').slice(0, 100),
        type: String(field.getAttribute('type') || field.tagName.toLowerCase()).slice(0, 30),
        required: !!field.required,
        autocomplete: String(field.getAttribute('autocomplete') || '').slice(0, 40),
      }));
      const hasPassword = fields.some(field => field.type.toLowerCase() === 'password');
      const externalAction = !!actionOrigin && actionOrigin !== originURL;
      forms.push({
        action, method: String(form.method || 'get').toUpperCase(),
        externalAction, hasPassword,
        fieldCount: fields.length, fields,
      });
      if (externalAction) securitySignals.push({
        severity: 'review', category: 'form', title: 'Form submits to another origin',
        evidence: action, detail: 'Review whether this external form destination is intentional.',
      });
      if (hasPassword && location.protocol !== 'https:' && !/^(localhost|127\.0\.0\.1|\[::1\])$/i.test(location.hostname)) {
        securitySignals.push({
          severity: 'high', category: 'transport', title: 'Password field on a non-HTTPS page',
          evidence: safeURL(location.href, true), detail: 'Credentials entered on an unencrypted page may be exposed in transit.',
        });
      }
    }

    const metaCsp = !!document.querySelector('meta[http-equiv="Content-Security-Policy" i]');
    const metaReferrer = getMeta('referrer');
    const metaRobots = getMeta('robots');
    const description = getMeta('description');
    const canonical = safeURL(document.querySelector('link[rel="canonical"]')?.href || '', true);
    const scriptNodes = Array.from(document.querySelectorAll('script[src]')).slice(0, 300);
    let externalScriptWithoutSRI = 0;
    let mixedContentCount = 0;
    for (const script of scriptNodes) {
      const url = safeURL(script.src, true);
      if (!url) continue;
      try {
        const u = new URL(url);
        if (u.origin !== originURL && !script.integrity) externalScriptWithoutSRI++;
        if (location.protocol === 'https:' && u.protocol === 'http:') mixedContentCount++;
      } catch {}
    }
    for (const el of Array.from(document.querySelectorAll('img[src],iframe[src],link[href],source[src]')).slice(0, 500)) {
      const raw = el.getAttribute('src') || el.getAttribute('href') || '';
      try {
        const u = new URL(raw, location.href);
        if (location.protocol === 'https:' && u.protocol === 'http:') mixedContentCount++;
      } catch {}
    }
    if (mixedContentCount) securitySignals.push({
      severity: 'high', category: 'transport', title: 'Potential mixed-content references',
      evidence: String(mixedContentCount) + ' HTTP resource reference(s) on an HTTPS page',
      detail: 'Browser policy may block some resources; review each referenced URL.',
    });
    if (externalScriptWithoutSRI) securitySignals.push({
      severity: 'info', category: 'integrity', title: 'External scripts without Subresource Integrity',
      evidence: String(externalScriptWithoutSRI) + ' external script(s) without an integrity attribute',
      detail: 'This is a review hint, not proof of a vulnerability; SRI is not suitable for every delivery pattern.',
    });
    if (newTabWithoutNoopener) securitySignals.push({
      severity: 'info', category: 'navigation', title: 'Links opening new tabs without noopener/noreferrer',
      evidence: String(newTabWithoutNoopener) + ' link(s) use target=_blank without a protective rel value',
      detail: 'Review opener isolation for links to untrusted or external destinations.',
    });
    if (!metaCsp) securitySignals.push({
      severity: 'info', category: 'headers', title: 'No CSP meta tag detected',
      evidence: 'No meta http-equiv Content-Security-Policy element found in the document',
      detail: 'This does not prove the response lacks a CSP header; page scripts cannot reliably inspect that header here.',
    });
    if (location.protocol !== 'https:' && !/^(localhost|127\.0\.0\.1|\[::1\])$/i.test(location.hostname)) securitySignals.push({
      severity: 'review', category: 'transport', title: 'Page is not using HTTPS',
      evidence: safeURL(location.href, true),
      detail: 'Confirm whether HTTP is expected for this environment.',
    });

    const storageKeys = storage => {
      const keys = [];
      try {
        for (let i = 0; i < storage.length && keys.length < 100; i++) {
          const key = storage.key(i);
          if (key === null) continue;
          // Report key names and approximate lengths only; never read out values into Deep Find.
          const value = storage.getItem(key);
          keys.push({ name: String(key).slice(0, 120), length: String(value || '').length });
        }
      } catch {}
      return keys;
    };
    const structuredDataTypes = [];
    for (const el of Array.from(document.querySelectorAll('script[type="application/ld+json"]')).slice(0, 40)) {
      try {
        const parsed = JSON.parse(el.textContent || '');
        const collectTypes = obj => {
          if (!obj || typeof obj !== 'object') return;
          if (obj['@type']) structuredDataTypes.push(String(obj['@type']).slice(0, 100));
          if (Array.isArray(obj)) obj.slice(0, 100).forEach(collectTypes);
          else if (obj['@graph']) collectTypes(obj['@graph']);
        };
        collectTypes(parsed);
      } catch {}
    }
    const dataAttributes = uniqStrings(
      Array.from(document.querySelectorAll('*')).slice(0, 1500).flatMap(el =>
        Array.from(el.attributes || []).map(attr => attr.name).filter(name => name.startsWith('data-'))
      ), 100
    );

    let serviceWorkerScope = '';
    try {
      if (navigator.serviceWorker?.controller) {
        const reg = await navigator.serviceWorker.getRegistration();
        serviceWorkerScope = reg?.scope ? safeURL(reg.scope, true) : 'controller active; registration scope unavailable';
      }
    } catch {}

    const assets = {
      scripts, styles, images, frames, manifests, icons,
      serviceWorkerControlled: !!navigator.serviceWorker?.controller,
      serviceWorkerScope,
      externalOrigins,
      performanceResources: Math.min(500, performance.getEntriesByType('resource').length),
    };
    const page = {
      url: pageURL,
      title: String(document.title || '').slice(0, 200),
      language: String(document.documentElement?.lang || '').slice(0, 30),
      description,
      generator,
      canonical,
      robots: metaRobots,
      referrerPolicy: metaReferrer,
      viewport: getMeta('viewport'),
      themeColor: getMeta('theme-color'),
      openGraphTitle: getMeta('og:title'),
      openGraphType: getMeta('og:type'),
      cspMetaPresent: metaCsp,
      structuredDataTypes: uniqStrings(structuredDataTypes, 50),
    };
    return {
      schemaVersion: 1, host: pageHost, capturedAt: Date.now(), page,
      technologies: technologies.slice(0, 40),
      counts: {
        scripts: scripts.length, styles: styles.length, images: images.length,
        frames: frames.length, manifests: manifests.length, routes: routes.length,
        links: document.querySelectorAll('a[href]').length,
        forms: formElements.length, externalLinks: externalLinkCount,
        externalOrigins: externalOrigins.length, storageKeys: storageKeys(localStorage).length + storageKeys(sessionStorage).length,
      },
      assets,
      routes: uniqStrings(routes, 250),
      forms: forms.slice(0, 80),
      storage: { localStorageKeys: storageKeys(localStorage), sessionStorageKeys: storageKeys(sessionStorage) },
      dataAttributes,
      securitySignals: securitySignals.slice(0, 100),
    };
  }

  // ── Main Analysis Routine ─────────────────────────────────────────────────

  async function _runAnalysis() {
    if (_analysisRunning) { _analysisPending = true; return; }
    _analysisRunning = true;
    const pageHost = location.hostname;
    const allEndpoints = [];
    const allGQL = [];
    let sourceChars = 0;
    let sourcesAnalyzed = 0;
    let sourceMapsAnalyzed = 0;

    try {
      const scripts = Array.from(document.querySelectorAll('script')).slice(0, MAX_SCRIPT_SOURCES);
      let cursor = 0;
      const worker = async () => {
        while (cursor < scripts.length && sourceChars < MAX_TOTAL_SOURCE_CHARS) {
          const script = scripts[cursor++];
          if (script.src) {
            let sourceURL;
            try { sourceURL = new URL(script.src, location.href).href; } catch { continue; }
            if (_scannedExternalSources.has(sourceURL)) continue;
            _scannedExternalSources.add(sourceURL);
            const budget = Math.max(1, Math.min(MAX_SOURCE_BYTES, MAX_TOTAL_SOURCE_CHARS - sourceChars));
            const text = await _fetchText(sourceURL, budget);
            if (!text) continue;
            sourceChars += text.length;
            sourcesAnalyzed++;
            const result = await _analyzeText(sourceURL, text, pageHost);
            allEndpoints.push(...result.endpoints);
            allGQL.push(...result.gqlOps);

            const sm = await _fetchSourceMap(sourceURL, text);
            if (sm && typeof sm === 'object') {
              sourceMapsAnalyzed++;
              const names = Array.isArray(sm.sources) ? sm.sources.slice(0, 500) : [];
              const contents = Array.isArray(sm.sourcesContent) ? sm.sourcesContent : [];
              for (const name of names) {
                if (typeof name !== 'string' || name.length > 2048) continue;
                allEndpoints.push({
                  url: name, type: 'sourcemap_source', confidence: 30,
                  evidence: 'source_map_source_name', source: sourceURL, host: pageHost,
                  discoveryMethod: 'source_map', observed: false,
                });
              }
              for (const content of contents.slice(0, 500)) {
                if (typeof content !== 'string' || !content || sourceChars >= MAX_TOTAL_SOURCE_CHARS) continue;
                const remain = MAX_TOTAL_SOURCE_CHARS - sourceChars;
                const bounded = content.slice(0, Math.min(MAX_SOURCE_BYTES, remain));
                sourceChars += bounded.length;
                if (!bounded) continue;
                const mapped = await _analyzeText(sourceURL + '[source-map]', bounded, pageHost);
                allEndpoints.push(...mapped.endpoints);
                allGQL.push(...mapped.gqlOps);
              }
            }
          } else if (script.textContent && script.textContent.trim()) {
            const bounded = script.textContent.slice(0, Math.min(MAX_SOURCE_BYTES, MAX_TOTAL_SOURCE_CHARS - sourceChars));
            sourceChars += bounded.length;
            if (!bounded) continue;
            sourcesAnalyzed++;
            const result = await _analyzeText('inline://' + pageHost, bounded, pageHost);
            allEndpoints.push(...result.endpoints);
            allGQL.push(...result.gqlOps);
          }
        }
      };
      await Promise.all(Array.from({ length: Math.min(4, scripts.length) }, () => worker()));

      allEndpoints.push(..._scanDOM(pageHost));
      allEndpoints.push(..._scanPerformanceResources(pageHost));
      allEndpoints.push(...await _scanCacheStorage(pageHost));

      const stateKeys = [
        '__NEXT_DATA__','__NUXT__','__APOLLO_STATE__','__REDUX_STATE__',
        '__INITIAL_STATE__','__PRELOADED_STATE__','__APP_STATE__','__STORE__',
        '__ENV__','ENV','_env','CONFIG','__config','__settings',
        '__REACT_QUERY_STATE__','__SWR_CACHE__','appConfig','apiConfig',
      ];
      for (const key of stateKeys) {
        try {
          if (globalThis[key] === undefined) continue;
          const value = typeof globalThis[key] === 'string'
            ? globalThis[key] : JSON.stringify(globalThis[key]);
          if (!value) continue;
          const bounded = value.slice(0, 100000);
          for (const item of _extractURLs(bounded)) {
            allEndpoints.push({ ...item, source: 'window_global:' + key, host: pageHost,
              discoveryMethod: 'runtime_config', observed: false });
          }
          allGQL.push(..._extractGQL(bounded));
        } catch {}
      }

      const byURL = new Map();
      for (const raw of allEndpoints) {
        const item = _normalizeEndpoint(raw, pageHost);
        if (!item) continue;
        let key = item.url;
        try { const parsed = new URL(item.url, location.href); parsed.hash = ''; key = parsed.href; } catch {}
        const existing = byURL.get(key);
        if (!existing) {
          byURL.set(key, { ...item, evidenceSources: [item.source] });
          continue;
        }
        existing.evidenceSources = Array.from(new Set([...(existing.evidenceSources || []), item.source])).slice(0, 12);
        existing.observed = existing.observed || item.observed;
        if (item.confidence > existing.confidence) {
          const sources = existing.evidenceSources;
          Object.assign(existing, item);
          existing.evidenceSources = sources;
        }
      }
      const filtered = Array.from(byURL.values()).filter(item => {
        return !/\.(?:css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|mp4|webm|pdf|map|txt\.gz)(?:[?#]|$)/i.test(item.url);
      }).slice(0, 2000);

      const siteProfile = await _scanSiteProfile(pageHost);

      const uniqueGQL = [];
      const gqlSeen = new Set();
      for (const op of allGQL) {
        const key = `${op.type || ''}:${op.name || ''}:${String(op.source || '').slice(0, 120)}`;
        if (gqlSeen.has(key)) continue;
        gqlSeen.add(key);
        uniqueGQL.push(op);
      }

      _post('ANALYSIS_RESULT', {
        host: pageHost, endpoints: filtered, graphqlOps: uniqueGQL.slice(0, 500), siteProfile,
        discovery: {
          scriptsSeen: scripts.length, scriptsAnalyzed: sourcesAnalyzed,
          sourceMapsAnalyzed, sourceChars,
          runtimeResources: filtered.filter(ep => ep.observed).length,
          endpointCandidates: filtered.length,
          limitReached: sourceChars >= MAX_TOTAL_SOURCE_CHARS,
        },
        timestamp: Date.now(),
      });
      console.debug(`[AGE Analyzer] ${filtered.length} endpoint candidates, ${uniqueGQL.length} GraphQL ops, ${siteProfile.technologies.length} technology clues and ${siteProfile.securitySignals.length} review signals on ${pageHost}`);
    } finally {
      _analysisRunning = false;
      if (_analysisPending) { _analysisPending = false; _scheduleAnalysis(500, false); }
    }
  }

  function _scheduleAnalysis(delay = 700, resetSources = false) {
    if (resetSources) _scannedExternalSources.clear();
    if (_analysisTimer) clearTimeout(_analysisTimer);
    _analysisTimer = setTimeout(() => { _analysisTimer = null; _runAnalysis(); }, delay);
  }

  if (typeof MutationObserver !== 'undefined' && document.documentElement) {
    const observer = new MutationObserver(records => {
      if (_autoRescans >= 12) return;
      const insertedScript = records.some(record =>
        Array.from(record.addedNodes || []).some(node =>
          node && node.nodeType === 1 &&
          (node.matches?.('script[src]') || node.querySelector?.('script[src]'))
        )
      );
      if (!insertedScript) return;
      _autoRescans++;
      _scheduleAnalysis(1000, false);
    });
    observer.observe(document.documentElement, { childList: true, subtree: true });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => _scheduleAnalysis(300, false), { once: true });
  } else {
    _scheduleAnalysis(300, false);
  }

})(typeof globalThis !== 'undefined' ? globalThis : window);
