// API Extraction Engine — Storage Manager
// Hot buffer: chrome.storage.local (ring buffer, capped at HOT_BUFFER_MAX)
// Cold archive: IndexedDB  (unbounded, paginated — never silently truncated)

import { HOT_BUFFER_MAX } from '../shared/constants.js';

const DB_NAME    = 'AGE_Archive';
const DB_VERSION = 1;

let _db = null;

// ─── Initialisation ───────────────────────────────────────────────────────────

export async function initStorage() {
  if (_db) return _db;
  _db = await _openDB();
  return _db;
}

function _openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);

    req.onupgradeneeded = (e) => {
      const db = e.target.result;

      if (!db.objectStoreNames.contains('captures')) {
        const s = db.createObjectStore('captures', { keyPath: 'id' });
        s.createIndex('timestamp', 'timestamp', { unique: false });
        s.createIndex('type',      'type',      { unique: false });
        s.createIndex('host',      'host',      { unique: false });
      }

      if (!db.objectStoreNames.contains('credentials')) {
        const s = db.createObjectStore('credentials', { keyPath: 'hash' });
        s.createIndex('type',      'type',      { unique: false });
        s.createIndex('timestamp', 'timestamp', { unique: false });
      }

      if (!db.objectStoreNames.contains('endpoints')) {
        const s = db.createObjectStore('endpoints', { keyPath: 'id' });
        s.createIndex('host',   'host',   { unique: false });
        s.createIndex('status', 'status', { unique: false });
        s.createIndex('type',   'type',   { unique: false });
      }

      if (!db.objectStoreNames.contains('graphql')) {
        db.createObjectStore('graphql', { keyPath: 'host' });
      }

      if (!db.objectStoreNames.contains('replays')) {
        const s = db.createObjectStore('replays', { keyPath: 'id' });
        s.createIndex('originalId', 'originalId', { unique: false });
        s.createIndex('timestamp',  'timestamp',  { unique: false });
      }
    };

    req.onsuccess = () => resolve(req.result);
    req.onerror   = () => reject(req.error);
  });
}

// ─── Hot Buffer (chrome.storage.local) ───────────────────────────────────────

export async function addHot(entry) {
  const { captures = [], captureIndex = 0 } = await chrome.storage.local.get(['captures', 'captureIndex']);
  const stamped = { ...entry, _hotIdx: captureIndex };
  if (captures.length >= HOT_BUFFER_MAX) captures.shift();
  captures.push(stamped);
  await chrome.storage.local.set({ captures, captureIndex: captureIndex + 1 });
  return stamped;
}

export async function getHot() {
  const { captures = [] } = await chrome.storage.local.get('captures');
  return captures;
}

export async function clearHot() {
  await chrome.storage.local.set({ captures: [], captureIndex: 0 });
}

// ─── Captures (IndexedDB) ─────────────────────────────────────────────────────

export async function archiveCapture(capture) {
  await initStorage();
  return _put('captures', capture);
}

/**
 * Get captures from IndexedDB, newest-first, with optional filters.
 * @param {{ page?, pageSize?, type?, host?, tag? }} opts
 */
export async function getCaptures({ page = 0, pageSize = 100, type, host, tag } = {}) {
  await initStorage();
  return new Promise((resolve, reject) => {
    const tx      = _db.transaction('captures', 'readonly');
    const store   = tx.objectStore('captures');
    const results = [];
    let   skipped = 0;
    const skip    = page * pageSize;

    const req = store.openCursor(null, 'prev');
    req.onsuccess = (e) => {
      const cursor = e.target.result;
      if (!cursor) { resolve(results); return; }

      const item = cursor.value;
      const ok   =
        (!type || item.type === type) &&
        (!host || item.host === host) &&
        (!tag  || (Array.isArray(item.tags) && item.tags.includes(tag)));

      if (ok) {
        if (skipped < skip) skipped++;
        else if (results.length < pageSize) results.push(item);
        else { resolve(results); return; }
      }
      cursor.continue();
    };
    req.onerror = () => reject(req.error);
  });
}

export async function getAllCaptures() {
  await initStorage();
  return _getAll('captures');
}

export async function getCaptureById(id) {
  await initStorage();
  return _get('captures', id);
}

export async function clearCaptures() {
  await initStorage();
  return _clear('captures');
}

// ─── Credentials (IndexedDB) ──────────────────────────────────────────────────

export async function upsertCredential(cred) {
  await initStorage();
  return _put('credentials', cred);
}

export async function getCredentials() {
  await initStorage();
  return _getAll('credentials');
}

export async function clearCredentials() {
  await initStorage();
  return _clear('credentials');
}

// ─── Endpoints (IndexedDB) ────────────────────────────────────────────────────

export async function upsertEndpoint(ep) {
  await initStorage();
  return _put('endpoints', ep);
}

export async function getEndpoints() {
  await initStorage();
  return _getAll('endpoints');
}

export async function clearEndpoints() {
  await initStorage();
  return _clear('endpoints');
}

// ─── GraphQL Schemas ──────────────────────────────────────────────────────────

export async function upsertGraphQL(host, schema, typeNames) {
  await initStorage();
  return _put('graphql', { host, schema, typeNames, timestamp: Date.now() });
}

export async function getGraphQL(host) {
  await initStorage();
  return _get('graphql', host);
}

export async function getAllGraphQL() {
  await initStorage();
  return _getAll('graphql');
}

// ─── Replays (IndexedDB) ──────────────────────────────────────────────────────

export async function archiveReplay(entry) {
  await initStorage();
  return _put('replays', entry);
}

export async function getReplays() {
  await initStorage();
  return _getAll('replays');
}

// ─── Passive Deep Find site profiles (browser-local only) ─────────────────────

export async function upsertSiteProfile(profile) {
  if (!profile || typeof profile.host !== 'string' || !profile.host) return false;
  const { siteProfiles = {} } = await chrome.storage.local.get('siteProfiles');
  const previous = siteProfiles[profile.host] || {};
  const caps = { technologies: 40, routes: 250, scripts: 120, styles: 100, images: 100, frames: 50, manifests: 10, icons: 20, externalOrigins: 100, forms: 80, securitySignals: 100, dataAttributes: 100 };

  const mergeStrings = (a, b, cap) => Array.from(new Set([...(Array.isArray(a) ? a : []), ...(Array.isArray(b) ? b : [])].filter(v => typeof v === 'string' && v))).slice(0, cap);
  const mergeObjects = (a, b, keyOf, cap, preferIncoming = true) => {
    const map = new Map();
    for (const item of [...(Array.isArray(a) ? a : []), ...(Array.isArray(b) ? b : [])]) {
      if (!item || typeof item !== 'object') continue;
      const key = String(keyOf(item) || '');
      if (!key) continue;
      if (!map.has(key) || preferIncoming) map.set(key, { ...(map.get(key) || {}), ...item });
    }
    return Array.from(map.values()).slice(-cap);
  };

  const latestPage = profile.page || {};
  const pageURL = String(latestPage.url || '');
  const incomingPage = {
    url: pageURL,
    title: String(latestPage.title || '').slice(0, 200),
    lastSeen: Number(profile.capturedAt) || Date.now(),
    counts: profile.counts && typeof profile.counts === 'object' ? profile.counts : {},
  };
  let pages = Array.isArray(previous.pages) ? previous.pages.slice() : [];
  const pageIndex = pages.findIndex(page => page?.url === incomingPage.url);
  if (pageIndex >= 0) pages[pageIndex] = { ...pages[pageIndex], ...incomingPage };
  else if (incomingPage.url) pages.push(incomingPage);
  pages = pages.slice(-100);

  const oldAssets = previous.assets || {};
  const newAssets = profile.assets || {};
  const assets = {
    scripts: mergeStrings(oldAssets.scripts, newAssets.scripts, caps.scripts),
    styles: mergeStrings(oldAssets.styles, newAssets.styles, caps.styles),
    images: mergeStrings(oldAssets.images, newAssets.images, caps.images),
    frames: mergeStrings(oldAssets.frames, newAssets.frames, caps.frames),
    manifests: mergeStrings(oldAssets.manifests, newAssets.manifests, caps.manifests),
    icons: mergeStrings(oldAssets.icons, newAssets.icons, caps.icons),
    serviceWorkerControlled: !!oldAssets.serviceWorkerControlled || !!newAssets.serviceWorkerControlled,
    serviceWorkerScope: newAssets.serviceWorkerScope || oldAssets.serviceWorkerScope || '',
    externalOrigins: mergeStrings(oldAssets.externalOrigins, newAssets.externalOrigins, caps.externalOrigins),
    performanceResources: Math.min(500, (Number(oldAssets.performanceResources) || 0) + (Number(newAssets.performanceResources) || 0)),
  };

  const technologies = mergeObjects(previous.technologies, profile.technologies, item => item.name, caps.technologies, false)
    .map(item => {
      const prior = (previous.technologies || []).find(old => old.name === item.name);
      const incoming = (profile.technologies || []).find(next => next.name === item.name);
      return incoming && (!prior || (Number(incoming.confidence) || 0) >= (Number(prior.confidence) || 0))
        ? { ...item, ...incoming } : item;
    });
  const routes = mergeStrings(previous.routes, profile.routes, caps.routes);
  const forms = mergeObjects(previous.forms, profile.forms,
    item => String(item.method || 'GET') + ' ' + String(item.action || ''), caps.forms, false)
    .map(form => {
      const oldFields = (previous.forms || []).find(old => String(old.method || 'GET') + ' ' + String(old.action || '') === String(form.method || 'GET') + ' ' + String(form.action || ''));
      const newFields = (profile.forms || []).find(next => String(next.method || 'GET') + ' ' + String(next.action || '') === String(form.method || 'GET') + ' ' + String(form.action || ''));
      const fields = mergeObjects(oldFields?.fields, newFields?.fields, field => String(field.name || '') + ':' + String(field.type || ''), 40);
      return { ...form, ...(newFields || {}), fields, fieldCount: fields.length };
    });
  const storageKeys = {
    localStorageKeys: mergeObjects(previous.storage?.localStorageKeys, profile.storage?.localStorageKeys, item => item.name, 100),
    sessionStorageKeys: mergeObjects(previous.storage?.sessionStorageKeys, profile.storage?.sessionStorageKeys, item => item.name, 100),
  };
  const securitySignals = mergeObjects(previous.securitySignals, profile.securitySignals,
    item => String(item.category || '') + '|' + String(item.title || '') + '|' + String(item.evidence || ''), caps.securitySignals);
  const dataAttributes = mergeStrings(previous.dataAttributes, profile.dataAttributes, caps.dataAttributes);

  const counts = {
    scripts: assets.scripts.length, styles: assets.styles.length, images: assets.images.length,
    frames: assets.frames.length, manifests: assets.manifests.length, routes: routes.length,
    links: pages.reduce((sum, page) => sum + (Number(page.counts?.links) || 0), 0),
    forms: forms.length,
    externalLinks: pages.reduce((sum, page) => sum + (Number(page.counts?.externalLinks) || 0), 0),
    externalOrigins: assets.externalOrigins.length,
    storageKeys: storageKeys.localStorageKeys.length + storageKeys.sessionStorageKeys.length,
    pagesScanned: pages.length,
  };
  const merged = {
    ...previous, ...profile, host: profile.host, capturedAt: Number(profile.capturedAt) || Date.now(),
    pages, counts, technologies, routes, assets, forms, storage: storageKeys,
    securitySignals, dataAttributes,
  };
  const next = { ...siteProfiles, [profile.host]: merged };
  const entries = Object.entries(next).sort((a, b) => (b[1]?.capturedAt || 0) - (a[1]?.capturedAt || 0));
  await chrome.storage.local.set({ siteProfiles: Object.fromEntries(entries.slice(0, 25)) });
  return true;
}

export async function getSiteProfile(host) {
  if (!host) return null;
  const { siteProfiles = {} } = await chrome.storage.local.get('siteProfiles');
  return siteProfiles[host] || null;
}

export async function getSiteProfiles() {
  const { siteProfiles = {} } = await chrome.storage.local.get('siteProfiles');
  return Object.values(siteProfiles).sort((a, b) => (b?.capturedAt || 0) - (a?.capturedAt || 0));
}

export async function clearSiteProfiles() {
  await chrome.storage.local.set({ siteProfiles: {} });
}

// ─── Stats ────────────────────────────────────────────────────────────────────

export async function getStats() {
  await initStorage();
  const [captureCount, credCount, endpointCount, replayCount] = await Promise.all([
    _count('captures'),
    _count('credentials'),
    _count('endpoints'),
    _count('replays'),
  ]);
  const hot   = await getHot();
  const hosts = new Set(hot.map(c => c.host).filter(Boolean));
  return {
    captureCount,
    credCount,
    endpointCount,
    replayCount,
    hotCount:    hot.length,
    uniqueHosts: hosts.size,
  };
}

// ─── Nuclear Clear ────────────────────────────────────────────────────────────

export async function clearAll() {
  await clearHot();
  await clearSiteProfiles();
  await Promise.all(['captures','credentials','endpoints','graphql','replays'].map(_clear));
}

// ─── IDB helpers ─────────────────────────────────────────────────────────────

function _put(store, data) {
  return new Promise((resolve, reject) => {
    const tx  = _db.transaction(store, 'readwrite');
    const req = tx.objectStore(store).put(data);
    req.onsuccess = () => resolve(req.result);
    req.onerror   = () => reject(req.error);
  });
}

function _get(store, key) {
  return new Promise((resolve, reject) => {
    const tx  = _db.transaction(store, 'readonly');
    const req = tx.objectStore(store).get(key);
    req.onsuccess = () => resolve(req.result ?? null);
    req.onerror   = () => reject(req.error);
  });
}

function _getAll(store) {
  return new Promise((resolve, reject) => {
    const tx  = _db.transaction(store, 'readonly');
    const req = tx.objectStore(store).getAll();
    req.onsuccess = () => resolve(req.result);
    req.onerror   = () => reject(req.error);
  });
}

function _count(store) {
  return new Promise((resolve, reject) => {
    const tx  = _db.transaction(store, 'readonly');
    const req = tx.objectStore(store).count();
    req.onsuccess = () => resolve(req.result);
    req.onerror   = () => reject(req.error);
  });
}

function _clear(store) {
  return new Promise((resolve, reject) => {
    const tx  = _db.transaction(store, 'readwrite');
    const req = tx.objectStore(store).clear();
    req.onsuccess = () => resolve();
    req.onerror   = () => reject(req.error);
  });
}
