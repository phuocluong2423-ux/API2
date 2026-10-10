// API Extraction Engine — Popup Controller
// Full featured: tabs, search, live updates, replay, copy-as-curl, exports, settings.

'use strict';

// ── Helpers ───────────────────────────────────────────────────────────────────

const $ = id => document.getElementById(id);

function sw(type, payload = {}) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({ type, payload }, res => {
      if (chrome.runtime.lastError) { reject(new Error(chrome.runtime.lastError.message)); return; }
      resolve(res);
    });
  });
}

function toast(msg, ms = 2000) {
  const el  = $('toast');
  el.textContent = msg;
  el.classList.add('show');
  setTimeout(() => el.classList.remove('show'), ms);
}

function fmtStatus(s) {
  if (!s || s === 0) return 'status-0';
  if (s < 300) return 'status-2xx';
  if (s < 400) return 'status-3xx';
  if (s < 500) return 'status-4xx';
  return 'status-5xx';
}

function fmtMethod(type, method) {
  if (type === 'websocket') return 'WS';
  if (type === 'eventsource') return 'SSE';
  if (type === 'beacon') return 'BEACON';
  return (method || 'GET').toUpperCase();
}

function splitURL(url) {
  try {
    const u = new URL(url);
    return { host: u.hostname, path: u.pathname + u.search };
  } catch { return { host: '', path: url }; }
}

function escapeHTML(s) {
  return String(s ?? '').replace(/[&<>"']/g, c =>
    ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));
}

function toCurl(capture) {
  const esc = s => String(s ?? '').replace(/'/g, "'\\''");
  const lines = [`curl -X ${esc(capture.method || 'GET')}`];
  for (const [k, v] of Object.entries(capture.requestHeaders || {})) {
    if (k.toLowerCase() === 'content-length') continue;
    lines.push(`  -H '${esc(k)}: ${esc(v)}'`);
  }
  const body = capture.requestBody;
  if (body && body !== '[empty]' && !['GET','HEAD'].includes((capture.method||'').toUpperCase()))
    lines.push(`  --data '${esc(body)}'`);
  lines.push(`  '${esc(capture.url || '')}'`);
  return lines.join(' \\\n');
}

function decodeJWT(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const dec = seg => JSON.parse(atob(seg.replace(/-/g,'+').replace(/_/,'/')
      .padEnd(seg.length + (4 - seg.length % 4) % 4, '=')));
    return { header: dec(parts[0]), payload: dec(parts[1]) };
  } catch { return null; }
}

// ── State ─────────────────────────────────────────────────────────────────────

let _allCaptures    = [];
let _credentials    = [];
let _endpoints      = [];
let _stats          = {};
let _settings       = {};
let _activeTab      = 'all';
let _searchQuery    = '';
let _expandedId     = null;
let _replayResults  = {};

// ── Init ─────────────────────────────────────────────────────────────────────

async function init() {
  await loadSettings();
  await refreshAll();
  bindEvents();
  listenForUpdates();
  applySettingsToUI();
}

async function refreshAll() {
  try {
    const [hot, creds, eps, stats] = await Promise.all([
      sw('GET_CAPTURES', { pageSize: 500 }),
      sw('GET_CREDENTIALS'),
      sw('GET_ENDPOINTS'),
      sw('GET_STATS'),
    ]);
    _allCaptures = Array.isArray(hot)   ? hot   : [];
    _credentials = Array.isArray(creds) ? creds : [];
    _endpoints   = Array.isArray(eps)   ? eps   : [];
    _stats       = stats || {};
    render();
    updateStats();
  } catch (err) {
    console.error('[AGE popup] refreshAll error', err);
  }
}

async function loadSettings() {
  _settings = await sw('GET_SETTINGS') || {};
}

// ── Rendering ─────────────────────────────────────────────────────────────────

function getFilteredItems() {
  const q = _searchQuery.trim().toLowerCase();

  switch (_activeTab) {
    case 'discovered':
      return _endpoints.filter(ep => {
        if (q && !ep.url?.toLowerCase().includes(q)) return false;
        return true;
      }).map(ep => ({
        ...ep,
        _isEndpoint: true,
        method: ep.type === 'graphql_op' ? 'GQL' : 'DISC',
        url: ep.url,
        tags: ep.tags || ['DISCOVERED'],
        responseStatus: ep.status || null,
      }));

    case 'probed':
      return _endpoints.filter(ep => ep.type === 'probed').map(ep => ({
        ...ep,
        _isEndpoint: true,
        method: 'PROBE',
        tags: ep.tags || ['PROBED'],
      }));

    case 'auth':
      return _allCaptures.filter(c =>
        c.tags?.includes('AUTH') &&
        (!q || _matchQuery(c, q)));

    case 'secrets':
      return _credentials.filter(c => {
        if (q && !c.value?.toLowerCase().includes(q) && !c.type?.toLowerCase().includes(q)) return false;
        return true;
      }).map(c => ({ ...c, _isCred: true, method: c.type?.toUpperCase() || 'CRED', url: c.sourceURL || '' }));

    case 'tokens':
      return _credentials.filter(c =>
        ['jwt','jwt_cookie','jwt_query','bearer_token','access_token','oauth_token'].includes(c.type) &&
        (!q || c.value?.toLowerCase().includes(q) || c.type?.toLowerCase().includes(q))
      ).map(c => ({ ...c, _isCred: true, method: 'JWT', url: c.sourceURL || '' }));

    case 'storage':
      return _credentials.filter(c =>
        c.type?.startsWith('storage_') &&
        (!q || c.value?.toLowerCase().includes(q))
      ).map(c => ({ ...c, _isCred: true, method: 'STOR', url: c.sourceURL || '' }));

    default: // 'all'
      return _allCaptures.filter(c => !q || _matchQuery(c, q));
  }
}

function _matchQuery(c, q) {
  return (
    c.url?.toLowerCase().includes(q) ||
    c.method?.toLowerCase().includes(q) ||
    String(c.responseStatus || '').includes(q) ||
    c.tags?.some(t => t.toLowerCase().includes(q)) ||
    c.credentials?.some(cr => cr.type?.toLowerCase().includes(q))
  );
}

function render() {
  const items    = getFilteredItems();
  const listWrap = $('list-wrap');

  if (items.length === 0) {
    listWrap.innerHTML = `
      <div id="empty-state">
        <div class="empty-icon">📡</div>
        <p>${_activeTab === 'all' ? 'No captures yet' : 'Nothing in this tab'}</p>
        <small>${_activeTab === 'all' ? 'Browse any page to start intercepting API calls' : 'Try a different filter'}</small>
      </div>`;
    return;
  }

  const html = items.map(item => renderRow(item)).join('');
  listWrap.innerHTML = html;

  // Re-attach expand listeners
  listWrap.querySelectorAll('.capture-row').forEach(row => {
    row.addEventListener('click', e => {
      if (e.target.closest('button')) return;
      const id = row.dataset.id;
      if (_expandedId === id) {
        _expandedId = null;
        row.classList.remove('expanded');
        const panel = row.nextElementSibling;
        if (panel?.classList.contains('detail-panel')) panel.classList.remove('visible');
      } else {
        document.querySelectorAll('.capture-row.expanded').forEach(r => r.classList.remove('expanded'));
        document.querySelectorAll('.detail-panel.visible').forEach(p => p.classList.remove('visible'));
        _expandedId = id;
        row.classList.add('expanded');
        const panel = row.nextElementSibling;
        if (panel?.classList.contains('detail-panel')) panel.classList.add('visible');
      }
    });
  });

  // Copy-as-curl buttons
  listWrap.querySelectorAll('.btn-copy-curl').forEach(btn => {
    btn.addEventListener('click', e => {
      e.stopPropagation();
      const item = items.find(i => i.id === btn.dataset.id || String(i._hotIdx) === btn.dataset.id);
      if (!item) return;
      navigator.clipboard.writeText(toCurl(item)).then(() => toast('✓ Copied as curl'));
    });
  });

  // Replay buttons
  listWrap.querySelectorAll('.btn-replay').forEach(btn => {
    btn.addEventListener('click', async e => {
      e.stopPropagation();
      const id   = btn.dataset.id;
      const item = items.find(i => String(i.id) === id || String(i._hotIdx) === id);
      if (!item) return;
      btn.textContent = '⟳ …';
      btn.disabled    = true;
      try {
        const result = await sw('REPLAY', { capture: item, options: { stripAnon: _settings.stripAnon } });
        _replayResults[id] = result;
        toast(`↻ ${result.response?.status || 'Error'} in ${result.duration}ms`);
        render(); // re-render to show diff
      } catch (err) {
        toast('Replay failed: ' + err.message, 3000);
      } finally {
        btn.textContent = '↻ Replay';
        btn.disabled    = false;
      }
    });
  });

  // Probe buttons (for discovered tab)
  listWrap.querySelectorAll('.btn-probe').forEach(btn => {
    btn.addEventListener('click', async e => {
      e.stopPropagation();
      const url = btn.dataset.url;
      btn.textContent = '⟳';
      const result = await sw('PROBE_URL', { url });
      toast(`Probe: ${result?.status || 'err'}`);
      btn.textContent = 'Probe';
    });
  });

  updateBadges(items.length);
}

function renderRow(item) {
  const id       = item.id || item.hash || Math.random().toString(36).slice(2);
  const method   = fmtMethod(item.type, item.method);
  const { host, path } = splitURL(item.url || '');
  const status   = item.responseStatus;
  const tags     = (item.tags || []).slice(0, 5);
  const credCount = item.credentialCount || 0;
  const isCred   = item._isCred;
  const isEndpoint = item._isEndpoint;
  const replay   = _replayResults[id];

  const methodClass = `method-${method}`;
  const statusClass = fmtStatus(status);

  let statusHtml = '';
  if (status !== null && status !== undefined) {
    statusHtml = `<span class="status-badge ${statusClass}">${status || '—'}</span>`;
  }

  let credBadge = '';
  if (credCount > 0) credBadge = `<span class="cred-badge">🔑 ${credCount}</span>`;

  const tagsHtml = tags.map(t => `<span class="tag tag-${t}">${t}</span>`).join('');

  let actionBtns = '';
  if (!isCred && !isEndpoint) {
    actionBtns = `
      <button class="btn btn-copy-curl" data-id="${escapeHTML(id)}" title="Copy as curl">⎘ curl</button>
      <button class="btn btn-replay" data-id="${escapeHTML(id)}" title="Replay this request">↻ Replay</button>`;
  }
  if (isEndpoint) {
    actionBtns = `<button class="btn btn-probe" data-url="${escapeHTML(item.url)}" title="Probe this endpoint">⚡ Probe</button>`;
  }

  // Build detail panel
  const detailHtml = renderDetailPanel(item, id, replay, isCred, isEndpoint);

  return `
    <div class="capture-row" data-id="${escapeHTML(id)}" role="listitem">
      <span class="method-badge ${methodClass}">${escapeHTML(method)}</span>
      ${statusHtml}
      <span class="capture-url truncate" title="${escapeHTML(item.url || '')}">
        <span class="host">${escapeHTML(host)}</span><span class="path">${escapeHTML(path)}</span>
      </span>
      <div class="tags">${tagsHtml}</div>
      ${credBadge}
      ${actionBtns}
    </div>
    ${detailHtml}`;
}

function renderDetailPanel(item, id, replay, isCred, isEndpoint) {
  const url = item.url || '';

  if (isCred) {
    const decoded = item.metadata?.decoded;
    let jwtSection = '';
    if (decoded) {
      const exp    = decoded.payload?.exp;
      const expStr = exp ? new Date(exp*1000).toISOString() : 'none';
      const isExpired = exp && Date.now() > exp * 1000;
      jwtSection = `
        <div class="jwt-item">
          <div class="jwt-header">${escapeHTML(JSON.stringify(decoded.header))}</div>
          <div class="jwt-payload">${escapeHTML(JSON.stringify(decoded.payload, null, 2))}</div>
          <div class="jwt-exp ${isExpired ? 'red' : 'green'}">exp: ${escapeHTML(expStr)} ${isExpired ? '⚠ EXPIRED' : '✓ valid'}</div>
        </div>`;
    }
    return `
      <div class="detail-panel" data-panel="${escapeHTML(id)}">
        <div class="detail-grid">
          <div class="detail-section">
            <div class="section-title">Type: ${escapeHTML(item.type)}</div>
            <div class="section-body">${jwtSection}<span style="word-break:break-all;color:var(--green)">${escapeHTML((item.value||'').slice(0,500))}</span></div>
          </div>
          <div class="detail-section">
            <div class="section-title">Source</div>
            <div class="section-body">${escapeHTML(item.sourceURL || '—')}</div>
          </div>
        </div>
        <div class="detail-actions">
          <button class="btn" onclick="navigator.clipboard.writeText('${escapeHTML(item.value||'')}').then(()=>{})">⎘ Copy Value</button>
        </div>
      </div>`;
  }

  if (isEndpoint) {
    return `
      <div class="detail-panel" data-panel="${escapeHTML(id)}">
        <div class="detail-grid">
          <div class="detail-section full">
            <div class="section-title">Endpoint: ${escapeHTML(item.type || 'discovered')}</div>
            <div class="section-body">URL: ${escapeHTML(url)}\nSource: ${escapeHTML(item.source||'—')}\nHost: ${escapeHTML(item.host||'—')}</div>
          </div>
        </div>
      </div>`;
  }

  // Full capture detail
  const reqH = JSON.stringify(item.requestHeaders || {}, null, 2);
  const resH = JSON.stringify(item.responseHeaders || {}, null, 2);
  const reqB = item.requestBody || '[empty]';
  const resB = item.responseBody || '[empty]';

  const replaySection = replay ? `
    <div class="detail-section full">
      <div class="section-title">↻ Last Replay — ${replay.response?.status || 'err'} in ${replay.duration}ms ${replay.fingerprintWarnings ? '⚠' : ''}</div>
      <div class="section-body">${escapeHTML((replay.diff || []).join('\n'))}\n\n${replay.fingerprintWarnings ? '⚠ ' + escapeHTML(replay.fingerprintWarnings.join('\n⚠ ')) : ''}
${replay.chainedTokens && Object.keys(replay.chainedTokens).length ? '\nChained tokens: ' + escapeHTML(JSON.stringify(replay.chainedTokens)) : ''}</div>
    </div>` : '';

  const wsSection = item.type === 'websocket' && item.frames ? `
    <div class="detail-section full">
      <div class="section-title">WebSocket Frames (sent: ${item.frames.sent?.length || 0}, received: ${item.frames.received?.length || 0})</div>
      <div class="section-body">${escapeHTML(JSON.stringify(item.frames, null, 2).slice(0,2000))}</div>
    </div>` : '';

  const sseSection = item.type === 'eventsource' && item.events ? `
    <div class="detail-section full">
      <div class="section-title">SSE Events (${item.events.length})</div>
      <div class="section-body">${escapeHTML(JSON.stringify(item.events, null, 2).slice(0,2000))}</div>
    </div>` : '';

  const cookieSection = item.httpOnlyCookies?.length ? `
    <div class="detail-section full">
      <div class="section-title">🍪 HttpOnly Cookies (${item.httpOnlyCookies.length}) — background capture</div>
      <div class="section-body">${escapeHTML(item.httpOnlyCookies.map(c => `${c.name}=${c.value}`).join('\n'))}</div>
    </div>` : '';

  return `
    <div class="detail-panel" data-panel="${escapeHTML(id)}">
      <div class="detail-grid">
        <div class="detail-section">
          <div class="section-title">Request Headers</div>
          <div class="section-body">${escapeHTML(reqH)}</div>
        </div>
        <div class="detail-section">
          <div class="section-title">Response Headers</div>
          <div class="section-body">${escapeHTML(resH)}</div>
        </div>
        <div class="detail-section">
          <div class="section-title">Request Body</div>
          <div class="section-body">${escapeHTML(reqB.slice(0,2000))}</div>
        </div>
        <div class="detail-section">
          <div class="section-title">Response Body</div>
          <div class="section-body">${escapeHTML(resB.slice(0,2000))}</div>
        </div>
        ${replaySection}
        ${wsSection}
        ${sseSection}
        ${cookieSection}
      </div>
      <div class="detail-actions">
        <button class="btn btn-copy-curl" data-id="${escapeHTML(id)}">⎘ Copy as curl</button>
        <button class="btn btn-replay" data-id="${escapeHTML(id)}">↻ Replay</button>
        <button class="btn" onclick="navigator.clipboard.writeText('${escapeHTML(url)}')">⎘ URL</button>
      </div>
    </div>`;
}

// ── Stats ─────────────────────────────────────────────────────────────────────

function updateStats() {
  $('stat-captures').textContent  = _stats.captureCount   || _allCaptures.length || 0;
  $('stat-hosts').textContent     = _stats.uniqueHosts    || '—';
  $('stat-creds').textContent     = _stats.credCount      || _credentials.length || 0;
  $('stat-endpoints').textContent = _stats.endpointCount  || _endpoints.length   || 0;
}

function updateBadges(filteredCount) {
  const authCount  = _allCaptures.filter(c => c.tags?.includes('AUTH')).length;
  const credCount  = _credentials.length;
  const tokenCount = _credentials.filter(c => ['jwt','jwt_cookie','bearer_token','access_token'].includes(c.type)).length;
  const storeCount = _credentials.filter(c => c.type?.startsWith('storage_')).length;
  const discCount  = _endpoints.filter(e => e.type !== 'probed').length;
  const probCount  = _endpoints.filter(e => e.type === 'probed').length;

  $('badge-all').textContent       = _allCaptures.length;
  $('badge-auth').textContent      = authCount;
  $('badge-secrets').textContent   = credCount;
  $('badge-tokens').textContent    = tokenCount;
  $('badge-storage').textContent   = storeCount;
  $('badge-discovered').textContent = discCount;
  $('badge-probed').textContent    = probCount;
}

// ── Event Binding ──────────────────────────────────────────────────────────────

function bindEvents() {
  // Tabs
  $('tabs').addEventListener('click', e => {
    const tab = e.target.closest('.tab');
    if (!tab) return;
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    tab.classList.add('active');
    _activeTab  = tab.dataset.tab;
    _expandedId = null;
    render();
  });

  // Search
  $('search').addEventListener('input', e => {
    _searchQuery = e.target.value;
    render();
  });

  // Prober toggle
  $('btn-prober').addEventListener('click', async () => {
    _settings.proberEnabled = !_settings.proberEnabled;
    await sw('UPDATE_SETTINGS', { proberEnabled: _settings.proberEnabled });
    $('btn-prober').classList.toggle('active', _settings.proberEnabled);
    toast(_settings.proberEnabled ? '⚡ Prober ON' : '⚡ Prober OFF');

    if (_settings.proberEnabled) {
      // Immediately probe discovery endpoints for current tab's host
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab?.url) {
        try {
          const u = new URL(tab.url);
          sw('PROBE_DISCOVERY', { origin: u.origin }).then(async () => {
            await refreshAll();
          });
        } catch {}
      }
    }
  });

  // Settings
  $('btn-settings').addEventListener('click', () => {
    $('settings-panel').classList.add('visible');
  });
  $('btn-close-settings').addEventListener('click', () => {
    $('settings-panel').classList.remove('visible');
  });
  $('btn-save-settings').addEventListener('click', saveSettings);

  // Clear
  $('btn-clear').addEventListener('click', async () => {
    if (!confirm('Clear all captures? (credentials and endpoints kept)')) return;
    await sw('CLEAR_DATA', { captures: true });
    _allCaptures = [];
    render();
    updateStats();
    toast('✓ Captures cleared');
  });

  // Exports
  $('btn-export-har').addEventListener('click',     () => doExport('EXPORT_HAR'));
  $('btn-export-openapi').addEventListener('click', () => doExport('EXPORT_OPENAPI'));
  $('btn-export-postman').addEventListener('click', () => doExport('EXPORT_POSTMAN'));
  $('btn-export-creds').addEventListener('click',   () => doExport('EXPORT_CREDS_JSON'));
  $('btn-export-env').addEventListener('click',     () => doExport('EXPORT_CREDS_ENV'));
  $('btn-export-gql').addEventListener('click',     () => doExport('EXPORT_GRAPHQL_SDL'));

  // Redact checkbox syncs with export
  $('chk-redacted').addEventListener('change', e => {
    _settings.redacted = e.target.checked;
  });

  // Side panel
  $('btn-sidepanel').addEventListener('click', async () => {
    await chrome.sidePanel?.open({ windowId: (await chrome.windows.getCurrent()).id });
    window.close();
  });
}

async function doExport(type) {
  const redacted = $('chk-redacted').checked;
  try {
    await sw(type, { redacted });
    toast('✓ Export downloaded');
  } catch (err) {
    toast('Export failed: ' + err.message, 3000);
  }
}

// ── Settings UI ───────────────────────────────────────────────────────────────

function applySettingsToUI() {
  $('s-prober-enabled').checked = !!_settings.proberEnabled;
  $('s-prober-delay').value     = _settings.proberDelay    ?? 250;
  $('s-aggressive').checked     = !!_settings.aggressiveMode;
  $('s-body-cap').value         = _settings.bodyCap        ?? 20480;
  $('s-hot-max').value          = _settings.hotBufferMax   ?? 2000;
  $('s-strip-anon').checked     = _settings.stripAnon      !== false;
  $('s-proxy-url').value        = _settings.proxyUrl       || '';
  $('s-user-agents').value      = (_settings.userAgents || []).join('\n');
  $('s-redacted').checked       = !!_settings.redacted;
  $('chk-redacted').checked     = !!_settings.redacted;
  $('btn-prober').classList.toggle('active', !!_settings.proberEnabled);
}

async function saveSettings() {
  const updated = {
    proberEnabled:  $('s-prober-enabled').checked,
    proberDelay:    parseInt($('s-prober-delay').value)   || 250,
    aggressiveMode: $('s-aggressive').checked,
    bodyCap:        parseInt($('s-body-cap').value)       || 20480,
    hotBufferMax:   parseInt($('s-hot-max').value)        || 2000,
    stripAnon:      $('s-strip-anon').checked,
    proxyUrl:       $('s-proxy-url').value.trim() || null,
    userAgents:     $('s-user-agents').value.split('\n').map(s => s.trim()).filter(Boolean),
    redacted:       $('s-redacted').checked,
  };
  _settings = updated;
  await sw('UPDATE_SETTINGS', updated);
  $('settings-panel').classList.remove('visible');
  applySettingsToUI();
  toast('✓ Settings saved');
}

// ── Live Updates ──────────────────────────────────────────────────────────────

function listenForUpdates() {
  chrome.runtime.onMessage.addListener((msg) => {
    if (!msg?.type) return;
    switch (msg.type) {
      case 'NEW_CAPTURE':
        refreshAll();
        // Flash new item indicator
        setTimeout(() => {
          const rows = document.querySelectorAll('.capture-row');
          if (rows.length > 0) rows[rows.length-1]?.classList.add('new-flash');
        }, 100);
        break;
      case 'ANALYSIS_UPDATE':
      case 'PROBE_UPDATE':
      case 'STORAGE_SCAN_COMPLETE':
        refreshAll();
        break;
      case 'GRAPHQL_SCHEMA_CAPTURED':
        toast(`📐 GQL schema captured: ${msg.data?.host}`);
        break;
    }
  });
}

// ── Boot ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', init);
