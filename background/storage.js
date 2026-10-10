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
  const next = { ...siteProfiles, [profile.host]: profile };
  const entries = Object.entries(next).sort((a, b) => (b[1]?.capturedAt || 0) - (a[1]?.capturedAt || 0));
  const bounded = Object.fromEntries(entries.slice(0, 25));
  await chrome.storage.local.set({ siteProfiles: bounded });
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
