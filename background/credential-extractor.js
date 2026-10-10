// API Extraction Engine — Credential Extractor
// Runs in the background service worker.
// Extracts JWTs, API keys, OAuth tokens, cloud credentials, signing material
// from captured requests/responses and from storage scan results.

import { sha256, isJWT, decodeJWT, jwtExpiry, parseCookieHeader } from '../shared/utils.js';
import { CREDENTIAL_KEY_RE, CLOUD_CRED_PATTERNS } from '../shared/constants.js';

// Pre-compiled cloud patterns (compiled once at module load)
const COMPILED_CLOUD = Object.entries(CLOUD_CRED_PATTERNS).map(([name, src]) => ({
  name,
  re: new RegExp(src, 'g'),
}));

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Extract all credentials from a single capture object.
 * Returns deduplicated Array<Credential>.
 */
export async function extractCredentials(capture) {
  const raw = [];

  if (capture.requestHeaders)  raw.push(...await fromHeaders(capture.requestHeaders,  capture.url, 'request_header'));
  if (capture.responseHeaders) raw.push(...await fromHeaders(capture.responseHeaders, capture.url, 'response_header'));
  if (capture.requestBody  && capture.requestBody  !== '[empty]') raw.push(...await fromText(capture.requestBody,  capture.url, 'request_body'));
  if (capture.responseBody && capture.responseBody !== '[empty]') raw.push(...await fromText(capture.responseBody, capture.url, 'response_body'));
  raw.push(...await fromURL(capture.url));

  return dedup(raw);
}

/**
 * Extract credentials from a storage scan payload.
 * storageData: { localStorage, sessionStorage, windowGlobals }
 */
export async function extractFromStorage(storageData) {
  const raw = [];
  for (const [ns, obj] of Object.entries(storageData)) {
    if (!obj || typeof obj !== 'object') continue;
    for (const [key, value] of Object.entries(obj)) {
      const val = typeof value === 'string' ? value : JSON.stringify(value);
      if (!val || val.length < 6) continue;
      const src = `storage://${ns}/${key}`;

      if (isJWT(val)) {
        const dec = decodeJWT(val);
        if (dec) raw.push(await makeCred('jwt', val, src, { decoded: dec, storageKey: key, ns }));
      } else if (key.match(CREDENTIAL_KEY_RE) && val.length > 8) {
        raw.push(await makeCred('storage_token', val, src, { storageKey: key, ns }));
      }

      // Recurse into JSON
      try {
        raw.push(...await fromJSON(JSON.parse(val), src, ns));
      } catch { /* not JSON */ }
    }
  }
  return dedup(raw);
}

// ─── Header Extraction ────────────────────────────────────────────────────────

async function fromHeaders(headers, sourceURL, sourceType) {
  const out = [];
  for (const [rawName, value] of Object.entries(headers)) {
    const name = rawName.toLowerCase();

    // Authorization: Bearer <token>
    if (name === 'authorization') {
      if (/^bearer\s+/i.test(value)) {
        const tok = value.replace(/^bearer\s+/i, '').trim();
        if (isJWT(tok)) {
          const dec = decodeJWT(tok);
          out.push(await makeCred('jwt', tok, sourceURL, { decoded: dec, header: rawName, source: sourceType }));
        } else {
          out.push(await makeCred('bearer_token', tok, sourceURL, { header: rawName, source: sourceType }));
        }
      } else if (/^basic\s+/i.test(value)) {
        const enc = value.replace(/^basic\s+/i, '').trim();
        let decoded = null;
        try { decoded = atob(enc); } catch { /* invalid b64 */ }
        out.push(await makeCred('basic_auth', enc, sourceURL, { header: rawName, decoded, source: sourceType }));
      } else if (/^(hmac|aws|signature|token)\s+/i.test(value)) {
        out.push(await makeCred('auth_signature', value, sourceURL, { header: rawName, source: sourceType }));
      }
    }

    // Cookie: header
    if (name === 'cookie') {
      const cookies = parseCookieHeader(value);
      for (const [cname, cval] of Object.entries(cookies)) {
        if (isJWT(cval)) {
          out.push(await makeCred('jwt_cookie', cval, sourceURL, {
            decoded: decodeJWT(cval), cookieName: cname, source: sourceType,
          }));
        } else if (cname.match(/sess|token|auth|jwt|id|access|refresh|sid/i) && cval.length > 8) {
          out.push(await makeCred('session_cookie', cval, sourceURL, { cookieName: cname, source: sourceType }));
        }
      }
    }

    // X-API-Key and friends
    if (rawName.match(CREDENTIAL_KEY_RE) && value.length > 8 &&
        !['content-type','accept','accept-language','cache-control'].includes(name)) {
      out.push(await makeCred('api_key_header', value, sourceURL, { header: rawName, source: sourceType }));
    }

    // Signing headers — capture for offline algorithm recovery
    if (/x-(?:signature|hmac|sign|hash|digest)/i.test(name)) {
      out.push(await makeCred('signing_material', value, sourceURL, {
        header: rawName,
        source: sourceType,
        note: 'Correlate with request body/timestamp to recover signing algorithm',
      }));
    }

    // AWS-specific
    if (/x-amz-(?:security-token|credential|signature)/i.test(name)) {
      out.push(await makeCred('aws_credential', value, sourceURL, { header: rawName, source: sourceType }));
    }

    // PKCE / OAuth code verifier
    if (/code.verifier|pkce|code.challenge/i.test(name)) {
      out.push(await makeCred('pkce_verifier', value, sourceURL, { header: rawName, source: sourceType }));
    }
  }
  return out;
}

// ─── URL Query Extraction ─────────────────────────────────────────────────────

async function fromURL(url) {
  const out = [];
  let u;
  try { u = new URL(url); } catch { return out; }
  for (const [key, value] of u.searchParams.entries()) {
    if (key.match(CREDENTIAL_KEY_RE) && value.length > 8) {
      if (isJWT(value)) {
        out.push(await makeCred('jwt_query', value, url, { decoded: decodeJWT(value), queryParam: key }));
      } else {
        out.push(await makeCred('api_key_query', value, url, { queryParam: key }));
      }
    }
  }
  return out;
}

// ─── Text / Body Extraction ───────────────────────────────────────────────────

async function fromText(text, sourceURL, sourceType) {
  if (!text || typeof text !== 'string') return [];
  const out = [];

  // JWTs embedded in arbitrary text
  for (const m of text.matchAll(/eyJ[A-Za-z0-9\-_]{4,}\.eyJ[A-Za-z0-9\-_]{4,}\.[A-Za-z0-9\-_]{4,}/g)) {
    const tok = m[0];
    const dec = decodeJWT(tok);
    if (dec) out.push(await makeCred('jwt', tok, sourceURL, { decoded: dec, source: sourceType }));
  }

  // Bearer tokens in text
  for (const m of text.matchAll(/bearer\s+([A-Za-z0-9\-_.~+/]+=*)/gi)) {
    const tok = m[1];
    if (!isJWT(tok) && tok.length > 8)
      out.push(await makeCred('bearer_token', tok, sourceURL, { source: sourceType }));
  }

  // Cloud credentials
  for (const { name, re } of COMPILED_CLOUD) {
    re.lastIndex = 0;
    for (const m of text.matchAll(re)) {
      out.push(await makeCred(name.toLowerCase(), m[0], sourceURL, { cloudType: name, source: sourceType }));
    }
  }

  // JSON: parse and recurse
  try {
    out.push(...await fromJSON(JSON.parse(text), sourceURL, sourceType));
  } catch {
    // Regex fallback for common token field names in non-JSON
    for (const m of text.matchAll(
      /['"]?(access_token|refresh_token|id_token|client_secret|api_key|apiKey|auth_token|oauth_token)['"]?\s*[:=]\s*['"]([^'"]{8,})['"]?/gi
    )) {
      out.push(await makeCred(m[1].toLowerCase(), m[2], sourceURL, { jsonKey: m[1], source: sourceType }));
    }
  }

  return out;
}

// ─── JSON Object Recursion ────────────────────────────────────────────────────

async function fromJSON(obj, sourceURL, source, depth = 0) {
  if (depth > 8 || !obj || typeof obj !== 'object') return [];
  const out = [];
  const entries = Array.isArray(obj) ? obj.entries() : Object.entries(obj);
  for (const [key, value] of entries) {
    if (typeof value === 'string' && value.length > 6) {
      const kStr = String(key);
      if (isJWT(value)) {
        out.push(await makeCred('jwt', value, sourceURL, {
          decoded: decodeJWT(value), jsonKey: kStr, source,
        }));
      } else if (kStr.match(/access_token|refresh_token|id_token|bearer|oauth/i)) {
        out.push(await makeCred('oauth_token', value, sourceURL, { jsonKey: kStr, source }));
      } else if (kStr.match(CREDENTIAL_KEY_RE) && !kStr.match(/url|host|name|label|title|desc|type|kind|icon/i)) {
        out.push(await makeCred('api_key', value, sourceURL, { jsonKey: kStr, source }));
      }
    } else if (value && typeof value === 'object') {
      out.push(...await fromJSON(value, sourceURL, source, depth + 1));
    }
  }
  return out;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

async function makeCred(type, value, sourceURL, metadata = {}) {
  const hash   = await sha256(value);
  const expiry = type.startsWith('jwt') && metadata.decoded
    ? jwtExpiry(metadata.decoded)
    : null;
  return {
    hash,
    type,
    value,
    sourceURL,
    metadata,
    expiry,
    timestamp: Date.now(),
    id: `${type}_${hash.slice(0, 8)}`,
  };
}

function dedup(creds) {
  const seen = new Map();
  for (const c of creds) if (!seen.has(c.hash)) seen.set(c.hash, c);
  return Array.from(seen.values());
}
