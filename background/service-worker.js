// API Extraction Engine — Background Service Worker
// Central hub: message routing, content-script registration, storage, coordination.
// This file is the entry point for the extension background context.

import { initStorage, addHot, archiveCapture, clearHot, upsertCredential, upsertEndpoint,
         getCaptures, getAllCaptures, getCredentials, getEndpoints, getStats,
         getAllGraphQL, upsertGraphQL, clearAll, clearCaptures, clearCredentials,
         clearEndpoints, getCaptureById, upsertSiteProfile, getSiteProfile } from './storage.js';
import { extractCredentials, extractFromStorage } from './credential-extractor.js';
import { configureProber, probeURL, probeDiscovery, probeGraphQL,
         probeCandidates, getProberConfig } from './prober.js';
import { replayRequest, getReplayLog, clearReplayLog,
         getChainedTokens, clearChainedTokens } from './replay.js';
import { exportHAR, exportOpenAPI, exportPostman,
         exportCredentialsJSON, exportCredentialsEnv,
         exportGraphQLSDL, exportDiscoveryReport, exportDeepFindReport, downloadFile } from './exporter.js';
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
    case 'GET_SITE_PROFILE': return getSiteProfile(payload.host);
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
    case 'EXPORT_DISCOVERY_REPORT': return _doExport('discovery_report', payload);
    case 'EXPORT_DEEP_FIND_REPORT': return _doExport('deep_find_report', payload);

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

async function _handleAnalysis({ endpoints = [], graphqlOps = [], host, discovery = {}, siteProfile = null } = {}, sender) {
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

    // Store a bounded, privacy-conscious site inventory. Bind it to the sender's
  // actual page host and discard fields that are not part of the Deep Find schema.
  const safeProfile = _sanitizeSiteProfile(siteProfile, sender);
  if (safeProfile) {
    await upsertSiteProfile(safeProfile);
    _broadcast('SITE_PROFILE_UPDATE', {
      host: safeProfile.host,
      technologyCount: safeProfile.technologies.length,
      routeCount: safeProfile.routes.length,
      formCount: safeProfile.forms.length,
      signalCount: safeProfile.securitySignals.length,
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

function _sanitizeSiteProfile(raw, sender) {
  if (!raw || typeof raw !== 'object' || typeof raw.host !== 'string') return null;
  let expectedHost = '';
  try { expectedHost = new URL(sender?.url || '').hostname.toLowerCase(); } catch {}
  const host = raw.host.toLowerCase().replace(/\.$/, '');
  if (!host || !expectedHost || host !== expectedHost.replace(/\.$/, '') || host.length > 253) return null;

  const clip = (value, max = 300) => typeof value === 'string' ? value.slice(0, max) : '';
  const number = (value, max = 1000000) => Number.isFinite(Number(value)) ? Math.max(0, Math.min(max, Number(value))) : 0;
  const safeURL = value => {
    if (typeof value !== 'string' || !value || value.length > 2048) return '';
    try {
      const u = new URL(value, 'https://' + host + '/');
      if (!['http:', 'https:'].includes(u.protocol)) return '';
      u.username = ''; u.password = ''; u.search = ''; u.hash = '';
      return u.href.slice(0, 1024);
    } catch { return ''; }
  };
  const safePathList = (value, cap = 250) => (Array.isArray(value) ? value : [])
    .filter(item => typeof item === 'string' && item.startsWith('/'))
    .map(item => item.split(/[?#]/)[0].slice(0, 300))
    .filter(Boolean).slice(0, cap);
  const safeURLList = (value, cap = 100) => Array.from(new Set(
    (Array.isArray(value) ? value : []).map(safeURL).filter(Boolean)
  )).slice(0, cap);
  const rawPage = raw.page && typeof raw.page === 'object' ? raw.page : {};
  const rawAssets = raw.assets && typeof raw.assets === 'object' ? raw.assets : {};
  const rawStorage = raw.storage && typeof raw.storage === 'object' ? raw.storage : {};
  const safeStorageKeys = value => (Array.isArray(value) ? value : []).slice(0, 100)
    .filter(item => item && typeof item === 'object')
    .map(item => ({ name: clip(item.name, 120), length: number(item.length, 1000000) }));
  return {
    schemaVersion: 1,
    host,
    capturedAt: number(raw.capturedAt || Date.now(), Date.now() * 2),
    page: {
      url: safeURL(rawPage.url),
      title: clip(rawPage.title, 200),
      language: clip(rawPage.language, 30),
      description: clip(rawPage.description, 300),
      generator: clip(rawPage.generator, 300),
      canonical: safeURL(rawPage.canonical),
      robots: clip(rawPage.robots, 300),
      referrerPolicy: clip(rawPage.referrerPolicy, 300),
      viewport: clip(rawPage.viewport, 300),
      themeColor: clip(rawPage.themeColor, 80),
      openGraphTitle: clip(rawPage.openGraphTitle, 200),
      openGraphType: clip(rawPage.openGraphType, 80),
      cspMetaPresent: rawPage.cspMetaPresent === true,
      structuredDataTypes: (Array.isArray(rawPage.structuredDataTypes) ? rawPage.structuredDataTypes : []).slice(0, 50).map(item => clip(item, 100)),
    },
    technologies: (Array.isArray(raw.technologies) ? raw.technologies : []).slice(0, 40)
      .filter(item => item && typeof item === 'object')
      .map(item => ({ name: clip(item.name, 100), evidence: clip(item.evidence, 180), confidence: number(item.confidence, 100) })),
    counts: {
      scripts: number(raw.counts?.scripts, 1000),
      styles: number(raw.counts?.styles, 1000),
      images: number(raw.counts?.images, 1000),
      frames: number(raw.counts?.frames, 500),
      manifests: number(raw.counts?.manifests, 100),
      routes: number(raw.counts?.routes, 1000),
      links: number(raw.counts?.links, 5000),
      forms: number(raw.counts?.forms, 500),
      externalLinks: number(raw.counts?.externalLinks, 5000),
      externalOrigins: number(raw.counts?.externalOrigins, 500),
      storageKeys: number(raw.counts?.storageKeys, 500),
    },
    assets: {
      scripts: safeURLList(rawAssets.scripts, 120),
      styles: safeURLList(rawAssets.styles, 100),
      images: safeURLList(rawAssets.images, 100),
      frames: safeURLList(rawAssets.frames, 50),
      manifests: safeURLList(rawAssets.manifests, 10),
      icons: safeURLList(rawAssets.icons, 20),
      serviceWorkerControlled: rawAssets.serviceWorkerControlled === true,
      serviceWorkerScope: safeURL(rawAssets.serviceWorkerScope),
      externalOrigins: safeURLList(rawAssets.externalOrigins, 100),
      performanceResources: number(rawAssets.performanceResources, 500),
    },
    routes: safePathList(raw.routes, 250),
    forms: (Array.isArray(raw.forms) ? raw.forms : []).slice(0, 80)
      .filter(form => form && typeof form === 'object')
      .map(form => ({
        action: safeURL(form.action),
        method: ['GET','POST','PUT','PATCH','DELETE','DIALOG'].includes(String(form.method || '').toUpperCase())
          ? String(form.method).toUpperCase() : 'GET',
        externalAction: form.externalAction === true,
        hasPassword: form.hasPassword === true,
        fieldCount: number(form.fieldCount, 40),
        fields: (Array.isArray(form.fields) ? form.fields : []).slice(0, 40)
          .filter(field => field && typeof field === 'object')
          .map(field => ({
            name: clip(field.name, 100), type: clip(field.type, 30),
            required: field.required === true, autocomplete: clip(field.autocomplete, 40),
          })),
      })),
    storage: {
      localStorageKeys: safeStorageKeys(rawStorage.localStorageKeys),
      sessionStorageKeys: safeStorageKeys(rawStorage.sessionStorageKeys),
    },
    dataAttributes: (Array.isArray(raw.dataAttributes) ? raw.dataAttributes : []).slice(0, 100).map(item => clip(item, 80)),
    securitySignals: (Array.isArray(raw.securitySignals) ? raw.securitySignals : []).slice(0, 100)
      .filter(item => item && typeof item === 'object')
      .map(item => ({
        severity: ['info','review','high'].includes(item.severity) ? item.severity : 'info',
        category: clip(item.category, 60), title: clip(item.title, 180),
        evidence: clip(item.evidence, 1024), detail: clip(item.detail, 500),
      })),
  };
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
    case 'deep_find_report': {
      const profile = await getSiteProfile(payload.host || '');
      if (!profile) return { ok: false, error: 'No Deep Find profile for this host yet. Reload the site and open AGE again.' };
      downloadFile(exportDeepFindReport(profile), 'age-deep-find-report.json', 'application/json');
      return { ok: true, host: profile.host, findings: (profile.technologies?.length || 0) + (profile.routes?.length || 0) + (profile.forms?.length || 0) + (profile.securitySignals?.length || 0) };
    }
    case 'discovery_report': {
      const [eps, schemas] = await Promise.all([getEndpoints(), getAllGraphQL()]);
      const ops = schemas.flatMap(item => (item.operations || []).map(op => ({ ...op, host: item.host })));
      downloadFile(exportDiscoveryReport(eps, ops, payload.host || ''), 'age-discovery-report.json', 'application/json');
      return { ok: true, count: eps.length };
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
