// API Extraction Engine — Shared Utilities
// Pure functions — no chrome.* calls, usable in any context

// ─── Crypto ──────────────────────────────────────────────────────────────────

/** SHA-256 of a string; returns lowercase hex. */
export async function sha256(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

/** Synchronous djb2 hash — for non-async dedup paths. */
export function djb2(str) {
  let h = 5381;
  for (let i = 0; i < str.length; i++) h = ((h << 5) + h) ^ str.charCodeAt(i);
  return (h >>> 0).toString(16);
}

/** Crypto-random UUID. */
export function randomUUID() {
  return typeof crypto.randomUUID === 'function'
    ? crypto.randomUUID()
    : 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
        const r = crypto.getRandomValues(new Uint8Array(1))[0] & 15;
        return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
      });
}

// ─── JWT ─────────────────────────────────────────────────────────────────────

const B64URL_RE = /^[A-Za-z0-9\-_]+$/;

/** Returns true if the string looks like a three-segment JWT. */
export function isJWT(s) {
  if (typeof s !== 'string') return false;
  const p = s.split('.');
  return p.length === 3 && p.every(seg => B64URL_RE.test(seg) && seg.length > 0);
}

/** Decode a JWT without verification. Returns { header, payload, raw } or null. */
export function decodeJWT(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const decode = seg => JSON.parse(atob(seg.replace(/-/g, '+').replace(/_/g, '/').padEnd(
      seg.length + (4 - seg.length % 4) % 4, '=')));
    return { header: decode(parts[0]), payload: decode(parts[1]), raw: token };
  } catch {
    return null;
  }
}

/** Extract JWT expiry as ms timestamp (null if not present). */
export function jwtExpiry(decoded) {
  return decoded?.payload?.exp ? decoded.payload.exp * 1000 : null;
}

// ─── URL / Path ───────────────────────────────────────────────────────────────

/** Parse a URL safely; returns URL object or null. */
export function safeURL(url, base) {
  try { return new URL(url, base); } catch { return null; }
}

/** Extract hostname or null. */
export function hostname(url) {
  return safeURL(url)?.hostname ?? null;
}

/** Return origin (scheme+host+port) or null. */
export function origin(url) {
  return safeURL(url)?.origin ?? null;
}

/** Parse query string into [[key,value]] pairs. */
export function queryPairs(url) {
  const u = safeURL(url);
  if (!u) return [];
  return Array.from(u.searchParams.entries());
}

// ─── Body / Text ──────────────────────────────────────────────────────────────

const BODY_CAP = 20480;

/** Truncate a string to cap bytes with a marker. */
export function truncate(s, cap = BODY_CAP) {
  if (typeof s !== 'string') s = String(s ?? '');
  return s.length > cap ? s.slice(0, cap) + '…[TRUNCATED]' : s;
}

/** Stringify any body-like value for capture. */
export function bodyToString(body) {
  if (body === null || body === undefined) return '[empty]';
  if (typeof body === 'string') return truncate(body);
  if (body instanceof URLSearchParams) return truncate(body.toString());
  if (body instanceof FormData) {
    const o = {};
    body.forEach((v, k) => { o[k] = v instanceof File ? `[File:${v.name}]` : v; });
    return truncate(JSON.stringify(o));
  }
  if (body instanceof ArrayBuffer || ArrayBuffer.isView(body)) {
    const bytes = body instanceof ArrayBuffer ? new Uint8Array(body) : new Uint8Array(body.buffer);
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes.slice(0, BODY_CAP));
    return text + (bytes.length > BODY_CAP ? '…[TRUNCATED]' : '');
  }
  if (body instanceof Blob) return `[Blob:${body.type}:${body.size}B]`;
  return truncate(String(body));
}

/** Convert Headers object or plain object to a plain object. */
export function headersToObject(headers) {
  if (!headers) return {};
  if (headers instanceof Headers) {
    const o = {};
    headers.forEach((v, k) => { o[k] = v; });
    return o;
  }
  return { ...headers };
}

/** Parse a raw Cookie header string into { name: value } map. */
export function parseCookieHeader(s) {
  const o = {};
  for (const part of s.split(';')) {
    const i = part.indexOf('=');
    if (i > 0) o[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return o;
}

/** Convert chrome.cookies array to Cookie header string. */
export function cookiesToHeader(cookies) {
  return cookies.map(c => `${c.name}=${c.value}`).join('; ');
}

// ─── Text Extraction ──────────────────────────────────────────────────────────

/**
 * Extract candidate API URLs and path literals from source text.
 * Returns Array<{ url: string, type: string }>.
 */
export function extractURLsFromText(text) {
  if (!text || typeof text !== 'string') return [];
  const seen = new Set();
  const add = (url, type) => {
    if (!seen.has(url) && url.length > 2 && url.length < 2048) {
      seen.add(url);
      results.push({ url, type });
    }
  };
  const results = [];

  // Absolute URLs
  for (const m of text.matchAll(/https?:\/\/[^\s"'<>`\])}\\,;]+/g))
    add(m[0].replace(/[,;.]+$/, ''), 'absolute');

  // Path literals near HTTP / API keywords
  for (const m of text.matchAll(
    /(?:fetch|axios|got|request|http(?:Client|Service)?|url|endpoint|api|graphql|baseURL?|path)\s*[=:(,+]\s*['"`]?(\/[A-Za-z0-9_\-./{}\[\]:?=&%#@!$*+~]+)/gi
  )) {
    const p = m[1].replace(/['"`]+$/, '').replace(/[,;.]+$/, '');
    if (p.length > 1) add(p, 'path_literal');
  }

  // Route-map object keys: { "/api/...": ... }
  for (const m of text.matchAll(
    /['"](\/(api|v\d+|graphql|rest|rpc|service|data|auth|user|admin|internal|mobile)[^'"]{1,300})['"]\s*:/g
  )) add(m[1], 'route_key');

  // Versioned prefixes
  for (const m of text.matchAll(/['"`](\/(?:v\d+|beta|internal|preview|staging|alpha)\/[^'"` \t\n]{1,200})['"`]/g))
    add(m[1].replace(/[,;.]+$/, ''), 'versioned');

  return results;
}

/**
 * Extract named + anonymous GraphQL operations from source text.
 * Returns Array<{ type, name, source }>.
 */
export function extractGraphQLOps(text) {
  if (!text) return [];
  const ops = [];

  // Named operations
  for (const m of text.matchAll(/(query|mutation|subscription)\s+(\w+)\s*(?:\([^)]*\))?\s*\{/g)) {
    const start = m.index;
    let depth = 0, i = start, limit = Math.min(text.length, start + 8000);
    while (i < limit) {
      if (text[i] === '{') depth++;
      else if (text[i] === '}') { depth--; if (depth === 0) break; }
      i++;
    }
    ops.push({ type: m[1], name: m[2], source: text.slice(start, Math.min(i + 1, start + 3000)) });
  }

  // gql`` tagged templates
  for (const m of text.matchAll(/gql`([\s\S]{4,3000}?)`/g)) {
    const src = m[1].trim();
    const tm = src.match(/^(query|mutation|subscription)/);
    ops.push({ type: tm ? tm[1] : 'fragment', name: 'anonymous', source: src.slice(0, 2000) });
  }

  return ops;
}

/**
 * Extract hostnames from text that differ from pageHost.
 * Returns string[].
 */
export function extractForeignHostnames(text, pageHost) {
  const hosts = new Set();
  for (const m of text.matchAll(/['"`]https?:\/\/([a-zA-Z0-9](?:[a-zA-Z0-9\-.]*[a-zA-Z0-9])?(?::\d+)?)/g)) {
    const h = m[1].toLowerCase();
    if (h !== pageHost && !h.endsWith('.example.com') && h.includes('.') && h.length < 253)
      hosts.add(h);
  }
  return Array.from(hosts);
}

// ─── Formatting ───────────────────────────────────────────────────────────────

/** Human-readable byte size. */
export function fmtBytes(n) {
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
  return (n / 1048576).toFixed(1) + ' MB';
}

/** Format a unix-ms timestamp as ISO string. */
export function fmtTime(ms) {
  return ms ? new Date(ms).toISOString() : '—';
}

/**
 * Generate a curl command from a capture object.
 */
export function toCurl(capture) {
  const esc = s => s.replace(/'/g, "'\\''");
  const lines = [`curl -X ${capture.method || 'GET'}`];
  for (const [k, v] of Object.entries(capture.requestHeaders || {})) {
    if (k.toLowerCase() === 'content-length') continue;
    lines.push(`  -H '${esc(k)}: ${esc(v)}'`);
  }
  if (capture.requestBody && !['GET', 'HEAD'].includes((capture.method || '').toUpperCase())) {
    const body = capture.requestBody === '[empty]' ? '' : capture.requestBody;
    if (body) lines.push(`  --data '${esc(body)}'`);
  }
  lines.push(`  '${esc(capture.url || '')}'`);
  return lines.join(' \\\n');
}

// ─── Template Variable Substitution ──────────────────────────────────────────

/**
 * Replace {{var}} tokens in a string.
 * context: { token, jwt, cookies: Cookie[], [key]: value }
 */
export function substituteVars(str, context = {}) {
  return str.replace(/\{\{([^}]+)\}\}/g, (match, key) => {
    const k = key.trim();
    if (k === 'random_uuid') return randomUUID();
    if (k === 'timestamp') return Date.now().toString();
    if (k === 'jwt' && context.jwt) return context.jwt;
    if (k === 'token' && context.token) return context.token;
    if (k.startsWith('cookie:') && Array.isArray(context.cookies)) {
      const name = k.slice(7);
      const c = context.cookies.find(x => x.name === name);
      return c ? c.value : match;
    }
    return context[k] !== undefined ? context[k] : match;
  });
}

// ─── Path Safety ──────────────────────────────────────────────────────────────

import { DESTRUCTIVE_PATTERNS } from './constants.js';

/** Returns true if path looks destructive (should skip in non-aggressive prober). */
export function isDestructive(path) {
  return DESTRUCTIVE_PATTERNS.some(re => re.test(path));
}

// ─── Deep Clone ───────────────────────────────────────────────────────────────

export function deepClone(obj) {
  try { return JSON.parse(JSON.stringify(obj)); } catch { return obj; }
}
