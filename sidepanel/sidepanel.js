// API Extraction Engine — Side Panel Controller
// Mirrors popup functionality in a persistent, taller panel.
// Uses chrome.runtime.connect for a long-lived port to the SW.

'use strict';

const $ = id => document.getElementById(id);

// ── SW Communication (long-lived port) ───────────────────────────────────────

const _port  = chrome.runtime.connect({ name: 'age-sidepanel' });
let   _reqId = 0;
const _pending = new Map();

_port.onMessage.addListener(msg => {
  const cb = _pending.get(msg.id);
  if (cb) { _pending.delete(msg.id); cb(msg.result, msg.error); }
});

function sw(type, payload = {}) {
  return new Promise((resolve, reject) => {
    const id = ++_reqId;
    _pending.set(id, (res, err) => err ? reject(new Error(err)) : resolve(res));
    _port.postMessage({ type, payload, id });
  });
}

function toast(msg, ms = 2000) {
  const el = $('sp-toast');
  el.textContent = msg;
  el.classList.add('show');
  setTimeout(() => el.classList.remove('show'), ms);
}

// ── State ─────────────────────────────────────────────────────────────────────

let _captures    = [];
let _credentials = [];
let _endpoints   = [];
let _stats       = {};
let _settings    = {};
let _activeTab   = 'all';
let _query       = '';
let _expandedId  = null;

// ── Init ─────────────────────────────────────────────────────────────────────

async function init() {
  _settings = (await sw('GET_SETTINGS')) || {};
  await refreshAll();
  bindEvents();
  listenUpdates();
  $('sp-btn-prober').classList.toggle('active', !!_settings.proberEnabled);
}

async function refreshAll() {
  const [caps, creds, eps, stats] = await Promise.all([
    sw('GET_CAPTURES', { pageSize: 1000 }),
    sw('GET_CREDENTIALS'),
    sw('GET_ENDPOINTS'),
    sw('GET_STATS'),
  ]);
  _captures    = Array.isArray(caps)  ? caps  : [];
  _credentials = Array.isArray(creds) ? creds : [];
  _endpoints   = Array.isArray(eps)   ? eps   : [];
  _stats       = stats || {};
  render();
  $('sp-stat-c').textContent = _stats.captureCount  || _captures.length;
  $('sp-stat-k').textContent = _stats.credCount      || _credentials.length;
  $('sp-stat-e').textContent = _stats.endpointCount  || _endpoints.length;
}

// ── Filter ────────────────────────────────────────────────────────────────────

function filtered() {
  const q = _query.toLowerCase();
  switch (_activeTab) {
    case 'auth':
      return _captures.filter(c => c.tags?.includes('AUTH') && (!q || _match(c, q)));
    case 'secrets':
      return _credentials.filter(c => !q || c.type?.includes(q) || c.value?.toLowerCase().includes(q))
        .map(c => ({ ...c, _isCred: true, method: c.type?.toUpperCase() || 'CRED' }));
    case 'tokens':
      return _credentials.filter(c =>
        ['jwt','jwt_cookie','bearer_token','access_token'].includes(c.type) &&
        (!q || c.value?.toLowerCase().includes(q))
      ).map(c => ({ ...c, _isCred: true, method: 'JWT' }));
    case 'discovered':
      return _endpoints.filter(ep => !ep.type?.includes('probed') &&
        (!q || ep.url?.toLowerCase().includes(q))
      ).map(ep => ({ ...ep, _isEp: true, method: ep.type === 'graphql_op' ? 'GQL' : 'DISC' }));
    case 'probed':
      return _endpoints.filter(ep => ep.type === 'probed' &&
        (!q || ep.url?.toLowerCase().includes(q))
      ).map(ep => ({ ...ep, _isEp: true, method: 'PROBE' }));
    default:
      return _captures.filter(c => !q || _match(c, q));
  }
}

function _match(c, q) {
  return c.url?.toLowerCase().includes(q) ||
    c.method?.toLowerCase().includes(q)    ||
    String(c.responseStatus || '').includes(q) ||
    c.tags?.some(t => t.toLowerCase().includes(q));
}

// ── Render ────────────────────────────────────────────────────────────────────

function render() {
  const items = filtered();
  const list  = $('sp-list');

  if (!items.length) {
    list.innerHTML = `<div class="sp-empty"><div class="sp-empty-icon">📡</div><p>Nothing here</p></div>`;
    return;
  }

  list.innerHTML = items.map(item => {
    const id     = item.id || item.hash || Math.random().toString(36).slice(2);
    const method = (item._isCred || item._isEp) ? item.method : _method(item);
    const { host, path } = _splitURL(item.url || '');
    const st     = item.responseStatus;
    const tags   = (item.tags || []).slice(0, 3);
    const stCls  = _stClass(st);

    return `
      <div class="sp-row${_expandedId === id ? ' expanded' : ''}" data-id="${_esc(id)}" role="listitem">
        <span class="sp-method ${method}">${_esc(method)}</span>
        ${st != null ? `<span class="sp-status ${stCls}">${st || '—'}</span>` : ''}
        <span class="sp-url" title="${_esc(item.url || '')}">
          <span class="host">${_esc(host)}</span><span style="color:var(--text2)">${_esc(path.slice(0,60))}</span>
        </span>
        <div class="sp-tags">${tags.map(t => `<span class="sp-tag ${t}">${t}</span>`).join('')}</div>
        ${item.credentialCount ? `<span style="font-size:9px;color:var(--cyan)">🔑${item.credentialCount}</span>` : ''}
      </div>
      <div class="sp-detail${_expandedId === id ? ' visible' : ''}" data-panel="${_esc(id)}">
        ${_renderDetail(item, id)}
      </div>`;
  }).join('');

  // Click-to-expand
  list.querySelectorAll('.sp-row').forEach(row => {
    row.addEventListener('click', e => {
      if (e.target.closest('button')) return;
      const id = row.dataset.id;
      if (_expandedId === id) {
        _expandedId = null;
      } else {
        _expandedId = id;
      }
      render();
    });
  });

  // Replay buttons
  list.querySelectorAll('.sp-btn-replay').forEach(btn => {
    btn.addEventListener('click', async e => {
      e.stopPropagation();
      const id   = btn.dataset.id;
      const item = items.find(i => String(i.id) === id);
      if (!item) return;
      btn.textContent = '⟳';
      try {
        const r = await sw('REPLAY', { capture: item, options: { stripAnon: _settings.stripAnon } });
        toast(`↻ ${r.response?.status || 'err'} ${r.duration}ms`);
        render();
      } catch (err) { toast('Replay err: ' + err.message, 3000); }
      btn.textContent = '↻';
    });
  });

  // Curl copy buttons
  list.querySelectorAll('.sp-btn-curl').forEach(btn => {
    btn.addEventListener('click', async e => {
      e.stopPropagation();
      const item = items.find(i => String(i.id) === btn.dataset.id);
      if (!item) return;
      await navigator.clipboard.writeText(_toCurl(item));
      toast('✓ curl copied');
    });
  });
}

function _renderDetail(item, id) {
  if (item._isCred) {
    const dec = item.metadata?.decoded;
    return `
      <div class="sp-detail-grid">
        <div class="sp-section full">
          <div class="sp-section-title">Type: ${_esc(item.type)} | ${_esc(item.sourceURL || '—')}</div>
          <div class="sp-section-body">${dec ? _esc(JSON.stringify(dec.payload, null, 2).slice(0,1000)) + '\n' : ''}${_esc((item.value || '').slice(0,300))}</div>
        </div>
      </div>
      <div class="sp-actions">
        <button class="sp-btn" onclick="navigator.clipboard.writeText('${_esc(item.value||'')}')">⎘ Copy</button>
      </div>`;
  }
  if (item._isEp) {
    return `
      <div class="sp-detail-grid">
        <div class="sp-section full">
          <div class="sp-section-title">${_esc(item.type || 'discovered')}</div>
          <div class="sp-section-body">URL: ${_esc(item.url || '')}\nSource: ${_esc(item.source || '—')}</div>
        </div>
      </div>`;
  }
  return `
    <div class="sp-detail-grid">
      <div class="sp-section">
        <div class="sp-section-title">Request Headers</div>
        <div class="sp-section-body">${_esc(JSON.stringify(item.requestHeaders || {}, null, 2).slice(0,1500))}</div>
      </div>
      <div class="sp-section">
        <div class="sp-section-title">Response Headers</div>
        <div class="sp-section-body">${_esc(JSON.stringify(item.responseHeaders || {}, null, 2).slice(0,1500))}</div>
      </div>
      <div class="sp-section">
        <div class="sp-section-title">Request Body</div>
        <div class="sp-section-body">${_esc((item.requestBody || '[empty]').slice(0,1500))}</div>
      </div>
      <div class="sp-section">
        <div class="sp-section-title">Response Body — ${item.responseStatus || 0}</div>
        <div class="sp-section-body">${_esc((item.responseBody || '[empty]').slice(0,1500))}</div>
      </div>
    </div>
    <div class="sp-actions">
      <button class="sp-btn sp-btn-curl" data-id="${_esc(id)}">⎘ curl</button>
      <button class="sp-btn sp-btn-replay" data-id="${_esc(id)}">↻ Replay</button>
    </div>`;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function _method(item) {
  if (item.type === 'websocket') return 'WS';
  if (item.type === 'eventsource') return 'SSE';
  if (item.type === 'beacon') return 'BEACON';
  return (item.method || 'GET').toUpperCase();
}

function _splitURL(url) {
  try { const u = new URL(url); return { host: u.hostname, path: u.pathname }; }
  catch { return { host: '', path: url }; }
}

function _stClass(s) {
  if (!s || s === 0) return 's0';
  if (s < 300) return 's2xx';
  if (s < 400) return 's3xx';
  if (s < 500) return 's4xx';
  return 's5xx';
}

function _esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, c =>
    ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));
}

function _toCurl(c) {
  const esc = s => String(s??'').replace(/'/g,"'\\''");
  const lines = [`curl -X ${esc(c.method||'GET')}`];
  for (const [k,v] of Object.entries(c.requestHeaders||{})) {
    if (k.toLowerCase()==='content-length') continue;
    lines.push(`  -H '${esc(k)}: ${esc(v)}'`);
  }
  const b = c.requestBody;
  if (b && b!=='[empty]' && !['GET','HEAD'].includes((c.method||'').toUpperCase()))
    lines.push(`  --data '${esc(b)}'`);
  lines.push(`  '${esc(c.url||'')}'`);
  return lines.join(' \\\n');
}

// ── Events ────────────────────────────────────────────────────────────────────

function bindEvents() {
  $('sp-tabs').addEventListener('click', e => {
    const tab = e.target.closest('.sp-tab');
    if (!tab) return;
    document.querySelectorAll('.sp-tab').forEach(t => t.classList.remove('active'));
    tab.classList.add('active');
    _activeTab  = tab.dataset.tab;
    _expandedId = null;
    render();
  });

  $('sp-search').addEventListener('input', e => { _query = e.target.value; render(); });

  $('sp-btn-prober').addEventListener('click', async () => {
    _settings.proberEnabled = !_settings.proberEnabled;
    await sw('UPDATE_SETTINGS', { proberEnabled: _settings.proberEnabled });
    $('sp-btn-prober').classList.toggle('active', _settings.proberEnabled);
    toast(_settings.proberEnabled ? '⚡ Prober ON' : '⚡ Prober OFF');
  });

  $('sp-btn-clear').addEventListener('click', async () => {
    if (!confirm('Clear captures?')) return;
    await sw('CLEAR_DATA', { captures: true });
    _captures = []; render();
    toast('✓ Cleared');
  });

  $('sp-btn-har').addEventListener('click', async () => {
    await sw('EXPORT_HAR', {}); toast('✓ HAR downloaded');
  });

  $('sp-btn-creds').addEventListener('click', async () => {
    await sw('EXPORT_CREDS_JSON', {}); toast('✓ Creds downloaded');
  });
}

function listenUpdates() {
  chrome.runtime.onMessage.addListener(msg => {
    if (['NEW_CAPTURE','ANALYSIS_UPDATE','PROBE_UPDATE','STORAGE_SCAN_COMPLETE'].includes(msg?.type)) {
      refreshAll();
    }
  });
}

document.addEventListener('DOMContentLoaded', init);
