// API Extraction Engine — Background Service Worker
// Central hub: message routing, content-script registration, storage, coordination.
// This file is the entry point for the extension background context.

import { initStorage, addHot, archiveCapture, clearHot, upsertCredential, upsertEndpoint,
         getCaptures, getAllCaptures, getCredentials, getEndpoints, getStats,
         getAllGraphQL, upsertGraphQL, clearAll, clearCaptures, clearCredentials,
         clearEndpoints, getCaptureById } from './storage.js';
import { extractCredentials, extractFromStorage } from './credential-extractor.js';
import { configureProber, probeURL, probeDiscovery, probeGraphQL,
         probeCandidates, getProberConfig } from './prober.js';
import { replayRequest, getReplayLog, clearReplayLog,
         getChainedTokens, clearChainedTokens } from './replay.js';
import { exportHAR, exportOpenAPI, exportPostman,
         exportCredentialsJSON, exportCredentialsEnv,
         exportGraphQLSDL, downloadFile } from './exporter.js';
import { sha256, randomUUID, origin } from '../shared/utils.js';

// ─── Init ─────────────────────────────────────────────────────────────────────

let _ready = false;

async function init() {
  if (_ready) return;
  _ready = true;
  await initStorage();
  await _registerContentScripts();
  await _applySettingsToModules();
  console.log('[AGE] Service worker ready');
}

async function _registerContentScripts() {
  try {
    const existing = await chrome.scripting.getRegisteredContentScripts();
    if (existing.length > 0) {
      await chrome.scripting.unregisterContentScripts({ ids: existing.map(s => s.id) });
    }
    await chrome.scripting.registerContentScripts([
      {
        id:                   'age-hooks',
        matches:              ['<all_urls>'],
        js:                   ['inject/hooks.js'],
        world:                'MAIN',
        runAt:                'document_start',
        allFrames:            true,
        matchOriginAsFallback: true,
      },
      {
        id:                   'age-analyzer',
        matches:              ['<all_urls>'],
        js:                   ['inject/analyzer.js'],
        world:                'MAIN',
        runAt:                'document_idle',
        allFrames:            true,
        matchOriginAsFallback: true,
      },
    ]);
    console.log('[AGE] Content scripts registered (MAIN world)');
  } catch (err) {
    // Graceful: extension may lack scripting permission on this install
    console.error('[AGE] registerContentScripts failed:', err.message);
  }
}

async function _applySettingsToModules() {
  const { settings = {} } = await chrome.storage.local.get('settings');
  configureProber({
    enabled:        settings.proberEnabled    ?? false,
    delayMs:        settings.proberDelay      ?? 250,
    aggressiveMode: settings.aggressiveMode   ?? false,
    proxyUrl:       settings.proxyUrl         ?? null,
    userAgents:     settings.userAgents       ?? [],
  });
}

// Default settings written on first install
async function _writeDefaultSettings() {
  const { settings } = await chrome.storage.local.get('settings');
  if (!settings) {
    await chrome.storage.local.set({
      settings: {
        proberEnabled:  false,
        proberDelay:    250,
        aggressiveMode: false,
        bodyCap:        20480,
        hotBufferMax:   2000,
        stripAnon:      true,
        redacted:       false,
        proxyUrl:       null,
        userAgents:     [],
      },
    });
  }
}

// ─── Lifecycle Hooks ──────────────────────────────────────────────────────────

chrome.runtime.onInstalled.addListener(async () => {
  await _writeDefaultSettings();
  await init();
});

chrome.runtime.onStartup.addListener(init);

// ─── Message Routing ──────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    if (!_ready) await init();
    try {
      if (!_isAuthorizedMessage(msg, sender)) return { error: 'Unauthorized message source' };
      return await _route(msg, sender);
    } catch (err) {
      console.error('[AGE] Handler error:', msg?.type, err);
      return { error: err.message };
    }
  })().then(sendResponse).catch(err => sendResponse({ error: err.message }));
  return true; // keep channel open for async
});

// Only extension-owned pages may use the privileged command router.
function _isExtensionURL(url) {
  try { return new URL(url).protocol === 'chrome-extension:' || new URL(url).protocol === 'moz-extension:'; }
  catch { return false; }
}

function _isAuthorizedMessage(msg, sender) {
  if (sender?.tab?.id != null) {
    return ['CAPTURE', 'ANALYSIS_RESULT', 'STORAGE_SCAN'].includes(msg?.type);
  }
  return _isExtensionURL(sender?.url || '');
}

// Side-panel long-lived port
chrome.runtime.onConnect.addListener(port => {
  if (port.name !== 'age-sidepanel' || !_isExtensionURL(port.sender?.url || '')) return;
  port.onMessage.addListener(async msg => {
    try {
      const result = await _route(msg, port.sender);
      port.postMessage({ id: msg.id, result });
    } catch (err) {
      port.postMessage({ id: msg.id, error: err.message });
    }
  });
});

async function _route(msg, sender) {
  const { type, payload = {} } = msg;
  switch (type) {
    // ── Ingestion (from bridge) ────────────────────────────────────────────
    case 'CAPTURE':          return _handleCapture(payload, sender);
    case 'ANALYSIS_RESULT':  return _handleAnalysis(payload, sender);
    case 'STORAGE_SCAN':     return _handleStorageScan(payload, sender);

    // ── Reads ─────────────────────────────────────────────────────────────
    case 'GET_CAPTURES':     return getCaptures(payload);
    case 'GET_ALL_CAPTURES': return getAllCaptures();
    case 'GET_CAPTURE_BY_ID':return getCaptureById(payload.id);
    case 'GET_CREDENTIALS':  return getCredentials();
    case 'GET_ENDPOINTS':    return getEndpoints();
    case 'GET_GRAPHQL':      return getAllGraphQL();
    case 'GET_STATS':        return getStats();
    case 'GET_REPLAY_LOG':   return getReplayLog();
    case 'GET_CHAINED_TOKENS': return getChainedTokens();
    case 'GET_SETTINGS':     return _getSettings();
    case 'GET_COOKIES':      return _getCookies(payload.url);

    // ── Actions ───────────────────────────────────────────────────────────
    case 'REPLAY':           return replayRequest(payload.capture, payload.options);
    case 'PROBE_URL':        return probeURL(payload.url, payload.headers);
    case 'PROBE_DISCOVERY':  return probeDiscovery(payload.origin, payload.headers);
    case 'PROBE_GRAPHQL':    return _handleProbeGraphQL(payload);
    case 'PROBE_CANDIDATES': return probeCandidates(payload.origin, payload.paths, payload.headers);
    case 'UPDATE_SETTINGS':  return _updateSettings(payload);
    case 'CLEAR_REPLAY_LOG': clearReplayLog(); return { ok: true };
    case 'CLEAR_CHAIN_TOKENS': clearChainedTokens(); return { ok: true };
    case 'CLEAR_DATA':       return _clearData(payload);

    // ── Exports ───────────────────────────────────────────────────────────
    case 'EXPORT_HAR':         return _doExport('har',         payload);
    case 'EXPORT_OPENAPI':     return _doExport('openapi',     payload);
    case 'EXPORT_POSTMAN':     return _doExport('postman',     payload);
    case 'EXPORT_CREDS_JSON':  return _doExport('creds_json',  payload);
    case 'EXPORT_CREDS_ENV':   return _doExport('creds_env',   payload);
    case 'EXPORT_GRAPHQL_SDL': return _doExport('graphql_sdl', payload);

    default:
      return { error: `Unknown message type: ${type}` };
  }
}

// ─── Capture Handler ──────────────────────────────────────────────────────────

async function _handleCapture(capture, sender) {
  if (!capture?.url) return { ok: false, reason: 'no_url' };
  // Skip extension-internal URLs and extension pages
  if (/^(chrome|moz)-extension:\/\//.test(capture.url)) return { ok: false, reason: 'internal' };

  const { settings = {} } = await chrome.storage.local.get('settings');
  const cap = settings.bodyCap ?? 20480;

  // Truncate bodies
  if (capture.requestBody  && capture.requestBody.length  > cap)
    capture.requestBody  = capture.requestBody.slice(0, cap)  + '…[TRUNCATED]';
  if (capture.responseBody && capture.responseBody.length > cap)
    capture.responseBody = capture.responseBody.slice(0, cap) + '…[TRUNCATED]';

  // Metadata
  capture.id        = capture.id || `${Date.now()}_${randomUUID().slice(0,8)}`;
  capture.timestamp = capture.timestamp || Date.now();
  try { capture.host = new URL(capture.url).hostname; } catch { capture.host = 'unknown'; }

  // Tag
  capture.tags = _classifyCapture(capture);

  // Extract credentials
  const creds = await extractCredentials(capture);
  for (const c of creds) await upsertCredential(c);

  if (creds.length > 0) {
    capture.credentials    = creds.map(c => ({ type: c.type, hash: c.hash, id: c.id }));
    capture.credentialCount = creds.length;
    if (!capture.tags.includes('AUTH')) capture.tags.push('AUTH');
  }

  // Harvest HttpOnly cookies from background (document.cookie can't see these)
  try {
    const all       = await chrome.cookies.getAll({ url: capture.url });
    const httpOnly  = all.filter(c => c.httpOnly);
    if (httpOnly.length > 0) {
      capture.httpOnlyCookies = httpOnly.map(({ name, value, domain, path, secure, httpOnly: ho, expirationDate }) =>
        ({ name, value, domain, path, secure, httpOnly: ho, expirationDate }));
    }
  } catch { /* cookies API may be unavailable for this URL */ }

  // Persist
  await addHot(capture);
  await archiveCapture(capture);

  // Notify open popup / side panel
  _broadcast('NEW_CAPTURE', { id: capture.id, tags: capture.tags, host: capture.host, credCount: creds.length });

  return { ok: true, id: capture.id, tags: capture.tags };
}

// ─── Analysis Handler ─────────────────────────────────────────────────────────

async function _handleAnalysis({ endpoints = [], graphqlOps = [], host, discovery = {} } = {}, sender) {
  // Persist provenance and confidence so the UI can distinguish static candidates
  // from resources actually observed in the browser performance timeline.
  for (const ep of endpoints.slice(0, 2000)) {
    if (!ep || typeof ep.url !== 'string' || ep.url.length > 2048) continue;
    const id = await sha256(ep.url + (ep.source || '') + (ep.host || host || ''));
    await upsertEndpoint({
      id, url: ep.url, source: ep.source, host: ep.host || host,
      type: ep.type || 'discovered', timestamp: Date.now(), tags: ['DISCOVERED'],
      confidence: Number.isFinite(ep.confidence) ? ep.confidence : 45,
      confidenceLabel: ep.confidenceLabel || 'low',
      evidence: ep.evidence || ep.type || 'candidate',
      evidenceSources: Array.isArray(ep.evidenceSources) ? ep.evidenceSources.slice(0, 12) : [ep.source || 'unknown'],
      discoveryMethod: ep.discoveryMethod || 'static_source',
      observed: ep.observed === true,
    });
  }

  // Store GraphQL operations as synthetic endpoints
  for (const op of graphqlOps) {
    const id = await sha256(`${op.type}:${op.name}:${host}`);
    await upsertEndpoint({
      id, url: `graphql://${host}/${op.type}/${op.name}`,
      source: op.source, host, type: 'graphql_op', timestamp: Date.now(),
      tags: ['DISCOVERED','GRAPHQL'], operationType: op.type, operationName: op.name,
    });
  }

  // Auto-probe path candidates if prober is enabled
  const { settings = {} } = await chrome.storage.local.get('settings');
  if (settings.proberEnabled) {
    const paths = endpoints.filter(e => !e.url.startsWith('http')).map(e => e.url);
    if (paths.length > 0) {
      const o = origin(`https://${host}`) || `https://${host}`;
      probeCandidates(o, paths).then(async results => {
        for (const r of results) {
          if (r.status > 0) {
            const id = await sha256(r.url + 'probed');
            await upsertEndpoint({ ...r, id, type: 'probed', tags: ['PROBED'] });
          }
        }
        _broadcast('PROBE_UPDATE', { count: results.length });
      });
    }
  }

  _broadcast('ANALYSIS_UPDATE', { endpointCount: endpoints.length, host, discovery });
  return { ok: true };
}

// ─── Storage Scan Handler ─────────────────────────────────────────────────────

async function _handleStorageScan(data, sender) {
  const creds = await extractFromStorage(data);
  for (const c of creds) await upsertCredential(c);
  _broadcast('STORAGE_SCAN_COMPLETE', { credentialCount: creds.length });
  return { ok: true, credentialCount: creds.length };
}

// ─── GraphQL Probe ────────────────────────────────────────────────────────────

async function _handleProbeGraphQL({ endpoint, host, headers = {} }) {
  const result = await probeGraphQL(endpoint, headers);
  if (result.schema || result.typeNames) {
    await upsertGraphQL(host || new URL(endpoint).hostname, result.schema, result.typeNames);
    _broadcast('GRAPHQL_SCHEMA_CAPTURED', { host, hasFullSchema: !!result.schema });
  }
  return result;
}

// ─── Export Handler ───────────────────────────────────────────────────────────

async function _doExport(type, payload) {
  const { settings = {} } = await chrome.storage.local.get('settings');
  const redacted = payload?.redacted ?? settings.redacted ?? false;

  switch (type) {
    case 'har': {
      const captures = await getAllCaptures();
      downloadFile(exportHAR(captures, redacted), 'age-captures.har', 'application/json');
      return { ok: true, count: captures.length };
    }
    case 'openapi': {
      const [captures, eps] = await Promise.all([getAllCaptures(), getEndpoints()]);
      downloadFile(exportOpenAPI(captures, eps, redacted), 'age-openapi.json', 'application/json');
      return { ok: true };
    }
    case 'postman': {
      const captures = await getAllCaptures();
      downloadFile(exportPostman(captures, redacted), 'age-postman-collection.json', 'application/json');
      return { ok: true };
    }
    case 'creds_json': {
      const creds = await getCredentials();
      downloadFile(exportCredentialsJSON(creds, redacted), 'age-credentials.json', 'application/json');
      return { ok: true, count: creds.length };
    }
    case 'creds_env': {
      const creds = await getCredentials();
      downloadFile(exportCredentialsEnv(creds, redacted), 'age-credentials.env', 'text/plain');
      return { ok: true };
    }
    case 'graphql_sdl': {
      const schemas  = await getAllGraphQL();
      const content  = schemas.length
        ? schemas.map(s => `# Host: ${s.host}\n` + exportGraphQLSDL(s.schema)).join('\n\n')
        : '# No GraphQL schemas captured\n';
      downloadFile(content, 'age-schema.graphql', 'text/plain');
      return { ok: true };
    }
    default: return { error: 'unknown export type' };
  }
}

// ─── Settings ─────────────────────────────────────────────────────────────────

async function _getSettings() {
  const { settings = {} } = await chrome.storage.local.get('settings');
  return settings;
}

async function _updateSettings(newSettings) {
  const { settings = {} } = await chrome.storage.local.get('settings');
  const merged = { ...settings, ...newSettings };
  await chrome.storage.local.set({ settings: merged });
  configureProber({
    enabled:        merged.proberEnabled    ?? false,
    delayMs:        merged.proberDelay      ?? 250,
    aggressiveMode: merged.aggressiveMode   ?? false,
    proxyUrl:       merged.proxyUrl         ?? null,
    userAgents:     merged.userAgents       ?? [],
  });
  return { ok: true, settings: merged };
}

async function _clearData({ captures, credentials, endpoints, all } = {}) {
  if (all) { await clearAll(); return { ok: true }; }
  if (captures) { await clearCaptures(); await clearHot(); }
  if (credentials) await clearCredentials();
  if (endpoints)   await clearEndpoints();
  return { ok: true };
}

async function _getCookies(url) {
  try   { return await chrome.cookies.getAll({ url }); }
  catch { return []; }
}

// ─── Capture Classification ────────────────────────────────────────────────────

function _classifyCapture(c) {
  const tags  = [];
  const url   = (c.url   || '').toLowerCase();
  const h     = c.requestHeaders || {};
  const st    = c.responseStatus || 0;

  if (st >= 400)             tags.push('ERR');
  else if (st >= 200)        tags.push('OK');

  if (h['authorization'] || h['Authorization'] ||
      h['x-api-key']     || h['X-API-Key'])     tags.push('AUTH');

  if (url.match(/\/(?:api|graphql|rest|rpc|service|data)\//)) tags.push('API');
  if (url.match(/\/v\d+\//))                                  tags.push('API');

  if (['POST','PUT','PATCH','DELETE'].includes(c.method))     tags.push('WRITE');

  if (url.match(/\/(?:auth|login|token|oauth|refresh|signup|register|session)/))
    tags.push('AUTH');

  if (url.match(/\/(?:secret|key|credential|password|config|env|admin|debug|internal|staging)/))
    tags.push('INTERESTING');

  if (url.match(/staging\.|\.internal\.|mobile-api\.|api-v\d+\.|preview\./))
    tags.push('INTERESTING');

  if (c.type === 'websocket') tags.push('WS');
  if (c.type === 'eventsource') tags.push('SSE');
  if (c.type === 'beacon')    tags.push('BEACON');

  return [...new Set(tags)];
}

// ─── UI Broadcast ─────────────────────────────────────────────────────────────

function _broadcast(type, data) {
  chrome.runtime.sendMessage({ type, data }).catch(() => {
    // Popup / side-panel not open — silently ignore
  });
}

// Bootstrap on SW load
init().catch(err => console.error('[AGE] Init failed:', err));
