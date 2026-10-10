// API Extraction Engine — Replay Engine
// Replays captured requests from the background context (bypasses page-level CORS).
// Supports host re-targeting, variable substitution, cookie injection, chained tokens,
// and fingerprint-risk detection.

import { substituteVars, cookiesToHeader, randomUUID, headersToObject } from '../shared/utils.js';
import { SKIP_REPLAY_HEADERS } from '../shared/constants.js';
import { archiveReplay } from './storage.js';

// In-memory replay log (most recent REPLAY_LOG_MAX entries)
const REPLAY_LOG_MAX = 500;
let _log = [];

// Chained token store: tokens extracted from previous replays, available for next
const _chainedTokens = {};

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Replay a captured request.
 *
 * @param {object} capture     Original capture from the archive
 * @param {object} options
 *   targetHost     string|null  Re-aim at a different host (e.g. staging)
 *   overrideHeaders object      Extra / replacement headers
 *   overrideBody   string|null  Replace request body
 *   overrideMethod string|null  Override HTTP method
 *   varContext     object       Extra vars for {{substitution}}
 *   stripAnon      bool         If true, strip identifying headers
 *   injectCookies  bool         If true (default), inject fresh cookies via chrome.cookies
 * @returns {Promise<ReplayEntry>}
 */
export async function replayRequest(capture, options = {}) {
  const {
    targetHost     = null,
    overrideHeaders = {},
    overrideBody   = null,
    overrideMethod = null,
    varContext     = {},
    stripAnon      = false,
    injectCookies  = true,
  } = options;

  // Build context for {{var}} substitution, including chained tokens
  const ctx = { ...varContext, ..._chainedTokens };

  // ── URL ──────────────────────────────────────────────────────────────────
  let url = substituteVars(capture.url || '', ctx);
  if (targetHost) {
    try {
      const p  = new URL(url);
      const th = new URL(targetHost.startsWith('http') ? targetHost : 'https://' + targetHost);
      p.protocol = th.protocol;
      p.hostname = th.hostname;
      p.port     = th.port;
      url        = p.toString();
    } catch { /* keep original */ }
  }

  // ── Fresh Cookies ─────────────────────────────────────────────────────────
  let freshCookies = [];
  if (injectCookies) {
    try {
      freshCookies = await chrome.cookies.getAll({ url: capture.url });
      ctx.cookies  = freshCookies;
    } catch { /* cookies API may be unavailable */ }
  }

  // ── Headers ───────────────────────────────────────────────────────────────
  const headers = {};
  if (!stripAnon && capture.requestHeaders) {
    for (const [k, v] of Object.entries(capture.requestHeaders)) {
      if (SKIP_REPLAY_HEADERS.has(k.toLowerCase())) continue;
      headers[k] = substituteVars(v, ctx);
    }
  }
  // User overrides take precedence
  for (const [k, v] of Object.entries(overrideHeaders)) {
    headers[k] = substituteVars(v, ctx);
  }
  // Inject fresh cookies (may override stale Cookie header)
  if (freshCookies.length > 0) {
    headers['Cookie'] = cookiesToHeader(freshCookies);
  }

  // ── Body ──────────────────────────────────────────────────────────────────
  const method = (overrideMethod || capture.method || 'GET').toUpperCase();
  let body = null;
  if (!['GET', 'HEAD'].includes(method)) {
    const raw = overrideBody !== null ? overrideBody : (capture.requestBody ?? '');
    body = raw && raw !== '[empty]' ? substituteVars(raw, ctx) : null;
  }

  // ── Fingerprint Risk Analysis ─────────────────────────────────────────────
  const fingerprintWarnings = detectFingerprintRisk(capture, headers);
  if (fingerprintWarnings.length > 0) {
    console.warn('[AGE Replay] Fingerprint risk detected:', fingerprintWarnings);
  }

  // ── Execute ───────────────────────────────────────────────────────────────
  const startTime = Date.now();
  let   responseStatus  = 0;
  let   responseHeaders = {};
  let   responseBody    = '';
  let   fetchError      = null;

  try {
    const res = await fetch(url, {
      method,
      headers,
      body:        body ?? undefined,
      credentials: 'include',
      redirect:    'follow',
    });

    responseStatus = res.status;
    res.headers.forEach((v, k) => { responseHeaders[k] = v; });

    const ct = responseHeaders['content-type'] || '';
    if (ct.includes('application/json') || ct.startsWith('text/')) {
      responseBody = await res.text();
    } else {
      const ab = await res.arrayBuffer();
      responseBody = `[Binary ${ab.byteLength} bytes]`;
    }
  } catch (err) {
    fetchError = err.message;
  }

  const duration = Date.now() - startTime;

  // ── Token Chaining ────────────────────────────────────────────────────────
  const extracted = _extractChainTokens(responseBody, responseHeaders);
  Object.assign(_chainedTokens, extracted);

  // ── Build Entry ───────────────────────────────────────────────────────────
  const entry = {
    id:                 `replay_${Date.now()}_${randomUUID().slice(0, 8)}`,
    originalId:         capture.id,
    timestamp:          Date.now(),
    request:            { url, method, headers, body },
    response:           { status: responseStatus, headers: responseHeaders, body: responseBody },
    duration,
    error:              fetchError,
    diff:               _diff(capture, responseStatus, responseBody),
    chainedTokens:      extracted,
    fingerprintWarnings: fingerprintWarnings.length > 0 ? fingerprintWarnings : null,
  };

  // Store
  _log.push(entry);
  if (_log.length > REPLAY_LOG_MAX) _log = _log.slice(-REPLAY_LOG_MAX);
  await archiveReplay(entry).catch(() => { /* best effort */ });

  return entry;
}

export function getReplayLog()  { return _log; }
export function clearReplayLog() { _log = []; }
export function getChainedTokens() { return { ..._chainedTokens }; }
export function clearChainedTokens() { Object.keys(_chainedTokens).forEach(k => delete _chainedTokens[k]); }

// ─── Fingerprint Risk Detection ───────────────────────────────────────────────

function detectFingerprintRisk(capture, headers) {
  const warnings = [];
  const resH   = capture.responseHeaders || {};
  const url    = capture.url || '';
  const allH   = { ...(capture.requestHeaders || {}), ...headers };

  // Cloudflare
  if (resH['cf-ray'] || resH['cf-cache-status']) {
    warnings.push(
      'Cloudflare detected. TLS fingerprint (JA3/JA4) of extension fetch may differ from ' +
      'original browser fingerprint. Replay may be challenged or blocked. ' +
      'Integration point: replace fetch() with a curl_cffi sidecar via nativeMessaging — ' +
      'see README § TLS Fingerprinting.'
    );
  }

  // Per-request signed tokens (CSRF, anti-bot)
  const tokenHeaders = ['cf-turnstile-response','x-recaptcha-token','x-captcha-response','x-csrf-token'];
  if (tokenHeaders.some(h => allH[h.toLowerCase()] || allH[h])) {
    warnings.push(
      'Anti-bot or CSRF token detected in request headers. ' +
      'These tokens are single-use and will fail on replay unless refreshed.'
    );
  }

  // HMAC / request signing
  const sigHeaders = Object.keys(allH).filter(k => /x-(?:signature|hmac|sign|hash|digest)/i.test(k));
  if (sigHeaders.length > 0) {
    warnings.push(
      `Signing headers detected (${sigHeaders.join(', ')}). ` +
      'The captured signature may not be valid for the replayed payload/timestamp. ' +
      'Signing material is stored for offline algorithm analysis.'
    );
  }

  return warnings;
}

// ─── Token Chaining ───────────────────────────────────────────────────────────

function _extractChainTokens(body, headers) {
  const tokens = {};

  // From response headers
  const authVal = headers['authorization'] || headers['x-auth-token'] || headers['x-access-token'];
  if (authVal) tokens['authorization'] = authVal;
  const setCookie = headers['set-cookie'];
  if (setCookie) tokens['set-cookie'] = setCookie;

  // From response body JSON
  try {
    const json = JSON.parse(body);
    const fields = ['access_token','token','jwt','id_token','refresh_token','auth_token','bearer'];
    const dig = (obj) => {
      if (!obj || typeof obj !== 'object') return;
      for (const f of fields) {
        if (typeof obj[f] === 'string') tokens[f] = obj[f];
      }
      for (const v of Object.values(obj)) {
        if (v && typeof v === 'object') dig(v);
      }
    };
    dig(json);
  } catch { /* not JSON */ }

  return tokens;
}

// ─── Diff ─────────────────────────────────────────────────────────────────────

function _diff(original, replayStatus, replayBody) {
  const lines = [];
  const origStatus = original.responseStatus || 0;
  if (origStatus !== replayStatus) {
    lines.push(`Status: ${origStatus} → ${replayStatus}`);
  } else {
    lines.push(`Status: ${replayStatus} (unchanged)`);
  }

  const origBody = original.responseBody || '';
  if (origBody === replayBody) {
    lines.push('Body: identical');
  } else {
    lines.push(`Body: changed (${origBody.length} → ${replayBody.length} chars)`);
  }

  return lines;
}
