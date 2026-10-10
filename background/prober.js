// API Extraction Engine — Live Endpoint Prober
// Runs in background service worker (not subject to page CORS).
// Sends HEAD / OPTIONS probes; rate-limited; skips destructive paths by default.

import {
  DISCOVERY_PATHS, GRAPHQL_INTROSPECTION, GRAPHQL_TYPE_ENUM,
  PROBER_DELAY_MS, PROBER_TIMEOUT_MS, ANON_STRIP_HEADERS,
} from '../shared/constants.js';
import { isDestructive, safeURL } from '../shared/utils.js';

// ─── Config ───────────────────────────────────────────────────────────────────

let cfg = {
  enabled:        false,
  delayMs:        PROBER_DELAY_MS,
  aggressiveMode: false,
  timeout:        PROBER_TIMEOUT_MS,
  proxyUrl:       null,
  userAgents:     [],
  _uaIdx:         0,
};

export function configureProber(overrides) {
  cfg = { ...cfg, ...overrides };
}

export function getProberConfig() {
  return { ...cfg };
}

// ─── Single URL Probe ─────────────────────────────────────────────────────────

/**
 * Probe one URL with HEAD (fallback OPTIONS).
 * Returns a probe-result object or null if probing is disabled.
 */
export async function probeURL(url, extraHeaders = {}) {
  if (!cfg.enabled) return null;

  const parsed = safeURL(url);
  if (!parsed) return { url, error: 'invalid_url', timestamp: Date.now() };

  if (!cfg.aggressiveMode && isDestructive(parsed.pathname)) {
    return { url, skipped: true, reason: 'destructive_path', timestamp: Date.now() };
  }

  const headers = _buildHeaders(extraHeaders);

  let result = await _probe(url, 'HEAD', headers);
  if (result.status === 405 || result.status === 0 || result.error) {
    await _sleep(50);
    result = await _probe(url, 'OPTIONS', headers);
  }

  await _sleep(cfg.delayMs);
  return result;
}

// ─── Discovery Pass ───────────────────────────────────────────────────────────

/**
 * Probe every well-known discovery path on an origin.
 * Returns Array<ProbeResult>.
 */
export async function probeDiscovery(origin, extraHeaders = {}) {
  const results = [];
  for (const path of DISCOVERY_PATHS) {
    const url = origin + path;
    const r = await probeURL(url, extraHeaders);
    if (r) results.push(r);
  }
  return results;
}

// ─── GraphQL Probe ────────────────────────────────────────────────────────────

/**
 * Probe a GraphQL endpoint: full introspection, then type-name enumeration.
 * Returns { endpoint, schema, typeNames, introspectionBlocked, timestamp }.
 */
export async function probeGraphQL(endpoint, extraHeaders = {}) {
  const headers = _buildHeaders({
    ...extraHeaders,
    'Content-Type': 'application/json',
    'Accept': 'application/json',
  });

  let schema              = null;
  let typeNames           = null;
  let introspectionBlocked = false;

  // Full introspection
  try {
    const res = await _timedFetch(endpoint, {
      method:      'POST',
      headers,
      body:        JSON.stringify({ query: GRAPHQL_INTROSPECTION }),
      credentials: 'omit',
    });
    if (res.ok) {
      const data = await res.json();
      if (data?.data?.__schema) {
        schema = data.data.__schema;
      } else if (data?.errors) {
        introspectionBlocked = true;
      }
    }
  } catch { /* network error */ }

  // Fallback: enumerate type names only
  if (!schema) {
    try {
      const res = await _timedFetch(endpoint, {
        method:      'POST',
        headers,
        body:        JSON.stringify({ query: GRAPHQL_TYPE_ENUM }),
        credentials: 'omit',
      });
      if (res.ok) {
        const data = await res.json();
        typeNames = data?.data?.__schema?.types?.map(t => ({ name: t.name, kind: t.kind })) ?? null;
      }
    } catch { /* network error */ }
  }

  return { endpoint, schema, typeNames, introspectionBlocked, timestamp: Date.now() };
}

// ─── Batch Candidate Probe ────────────────────────────────────────────────────

/**
 * Probe a list of path strings against an origin with rate limiting.
 * @param {string}   origin
 * @param {string[]} paths    Absolute URLs or root-relative paths
 * @param {object}   extraHeaders
 * @returns {Promise<Array<ProbeResult>>}
 */
export async function probeCandidates(origin, paths, extraHeaders = {}) {
  const results = [];
  for (const p of paths) {
    const url = p.startsWith('http') ? p : origin + (p.startsWith('/') ? p : '/' + p);
    const r = await probeURL(url, extraHeaders);
    if (r) results.push(r);
  }
  return results;
}

// ─── Internal Helpers ─────────────────────────────────────────────────────────

async function _probe(url, method, headers) {
  try {
    const res = await _timedFetch(url, { method, headers, credentials: 'omit', redirect: 'follow' });
    const resHeaders = {};
    res.headers.forEach((v, k) => { resHeaders[k] = v; });
    return {
      url, method,
      status:     res.status,
      statusText: res.statusText,
      headers:    resHeaders,
      allow:      resHeaders['allow'] ?? '',
      cors: {
        allowOrigin:      resHeaders['access-control-allow-origin'],
        allowMethods:     resHeaders['access-control-allow-methods'],
        allowHeaders:     resHeaders['access-control-allow-headers'],
        allowCredentials: resHeaders['access-control-allow-credentials'],
        exposeHeaders:    resHeaders['access-control-expose-headers'],
      },
      server:    resHeaders['server'],
      timestamp: Date.now(),
      probed:    true,
    };
  } catch (err) {
    return {
      url, method,
      status:    0,
      error:     err.name === 'AbortError' ? 'timeout' : err.message,
      timestamp: Date.now(),
      probed:    true,
    };
  }
}

function _timedFetch(url, opts) {
  const ctrl = new AbortController();
  const id   = setTimeout(() => ctrl.abort(), cfg.timeout);
  return fetch(url, { ...opts, signal: ctrl.signal }).finally(() => clearTimeout(id));
}

function _buildHeaders(extra = {}) {
  // Build minimal, non-identifying headers.
  // Strip all ANON_STRIP_HEADERS by simply not including them.
  const base = {
    'Accept':          'application/json, text/plain, */*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
  };

  // User-agent rotation (only if user has configured a list)
  if (cfg.userAgents.length > 0) {
    base['User-Agent'] = cfg.userAgents[cfg._uaIdx % cfg.userAgents.length];
    cfg._uaIdx++;
  }

  // Merge extra headers, but honour the anon strip list
  for (const [k, v] of Object.entries(extra)) {
    if (!ANON_STRIP_HEADERS.has(k.toLowerCase())) base[k] = v;
  }

  return base;
}

function _sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}
