// API Extraction Engine — Export Module
// Produces: HAR 1.2, OpenAPI 3.1, Postman v2.1, Credential JSON, .env, GraphQL SDL
// All exports are local blobs — no server, no telemetry, no phoning home.

import { randomUUID, queryPairs } from '../shared/utils.js';

// ─── HAR 1.2 ─────────────────────────────────────────────────────────────────

export function exportHAR(captures, redacted = false) {
  return JSON.stringify({
    log: {
      version:  '1.2',
      creator:  { name: 'API Extraction Engine', version: '1.0.0' },
      browser:  { name: 'Chrome', version: 'N/A' },
      pages:    [],
      entries:  captures.map(c => _captureToHAREntry(c, redacted)),
    },
  }, null, 2);
}

function _captureToHAREntry(c, redacted) {
  const entry = {
    startedDateTime: new Date(c.timestamp || Date.now()).toISOString(),
    time:            c.duration || -1,
    request: {
      method:      c.method || 'GET',
      url:         redacted ? _redactURL(c.url) : (c.url || ''),
      httpVersion: 'HTTP/1.1',
      cookies:     [],
      headers:     _headersToHAR(c.requestHeaders || {}, redacted),
      queryString: queryPairs(c.url).map(([name, value]) => ({ name, value: redacted && /token|key|secret|auth|sig|pass|credential|session/i.test(name) ? '[REDACTED]' : value })),
      headersSize: -1,
      bodySize:    c.requestBody ? c.requestBody.length : 0,
    },
    response: {
      status:      c.responseStatus || 0,
      statusText:  c.responseStatusText || '',
      httpVersion: 'HTTP/1.1',
      cookies:     [],
      headers:     _headersToHAR(c.responseHeaders || {}, redacted),
      content: {
        size:     c.responseBody ? c.responseBody.length : 0,
        mimeType: (c.responseHeaders || {})['content-type'] || 'application/octet-stream',
        text:     redacted ? '[REDACTED]' : (c.responseBody || ''),
      },
      redirectURL: '',
      headersSize: -1,
      bodySize:    c.responseBody ? c.responseBody.length : 0,
    },
    cache:    {},
    timings:  { send: 0, wait: c.duration || 0, receive: 0 },
    _tags:    c.tags || [],
    _type:    c.type || 'fetch',
    _host:    c.host || '',
  };

  if (c.requestBody && c.requestBody !== '[empty]' && !['GET','HEAD'].includes(c.method)) {
    const ct = (c.requestHeaders || {})['content-type'] || 'application/json';
    entry.request.postData = {
      mimeType: ct,
      text:     redacted ? '[REDACTED]' : c.requestBody,
    };
  }

  return entry;
}

const SENSITIVE_HEADERS = new Set([
  'authorization','cookie','set-cookie','x-api-key','x-auth-token',
  'x-access-token','x-secret','proxy-authorization',
]);

function _headersToHAR(headers, redacted) {
  return Object.entries(headers).map(([name, value]) => ({
    name,
    value: redacted && SENSITIVE_HEADERS.has(name.toLowerCase()) ? '[REDACTED]' : value,
  }));
}

function _redactURL(url) {
  try {
    const u = new URL(url);
    u.searchParams.forEach((v, k) => {
      if (/token|key|secret|auth|sig|pass|credential/i.test(k)) u.searchParams.set(k, '[REDACTED]');
    });
    return u.toString();
  } catch { return url; }
}

// ─── OpenAPI 3.1 ─────────────────────────────────────────────────────────────

export function exportOpenAPI(captures, discoveredEndpoints = [], redacted = false) {
  const paths   = {};
  const servers = new Set();

  for (const c of captures) {
    try {
      const u      = new URL(c.url);
      const path   = u.pathname;
      const method = (c.method || 'GET').toLowerCase();
      servers.add(u.origin);

      if (!paths[path]) paths[path] = {};
      if (!paths[path][method]) {
        paths[path][method] = {
          operationId: `${method}_${path.replace(/[^a-zA-Z0-9]/g, '_').replace(/__+/g, '_')}`,
          summary:     `${c.method} ${path}`,
          tags:        c.tags || [],
          parameters:  _buildParameters(u.searchParams, c.requestHeaders || {}, redacted),
          responses:   {},
        };
      }

      const status = String(c.responseStatus || 200);
      const ct     = ((c.responseHeaders || {})['content-type'] || 'application/json').split(';')[0].trim();
      paths[path][method].responses[status] = {
        description: c.responseStatusText || 'Response',
        content:     { [ct]: { schema: { type: 'object' } } },
      };

      if (c.requestBody && c.requestBody !== '[empty]' && !['get','head'].includes(method)) {
        const bct = ((c.requestHeaders || {})['content-type'] || 'application/json').split(';')[0].trim();
        paths[path][method].requestBody = {
          required: true,
          content:  { [bct]: { schema: { type: 'object' } } },
        };
      }
    } catch { /* skip malformed */ }
  }

  // Merge discovered (static-analysis) endpoints
  for (const ep of discoveredEndpoints) {
    const rawURL = ep.url || '';
    const path   = rawURL.startsWith('/') ? rawURL.split('?')[0] : (() => {
      try { return new URL(rawURL).pathname; } catch { return null; }
    })();
    if (!path) continue;
    if (!paths[path]) {
      paths[path] = {
        get: {
          operationId: `discovered_${path.replace(/[^a-zA-Z0-9]/g,'_')}`,
          summary:     `Discovered: ${path}`,
          tags:        ['discovered'],
          parameters:  [],
          responses:   { '200': { description: 'OK' } },
          'x-source':  ep.source || 'static_analysis',
          'x-type':    ep.type  || 'discovered',
        },
      };
    }
  }

  return JSON.stringify({
    openapi: '3.1.0',
    info:    {
      title:       'API Extraction Engine — Discovered Surface',
      version:     '1.0.0',
      description: 'Auto-generated from live traffic capture and static analysis',
    },
    servers:    Array.from(servers).map(url => ({ url })),
    paths,
    components: {
      securitySchemes: {
        bearerAuth: { type: 'http',   scheme: 'bearer', bearerFormat: 'JWT' },
        apiKeyHeader: { type: 'apiKey', in: 'header',   name: 'X-API-Key' },
        apiKeyQuery:  { type: 'apiKey', in: 'query',    name: 'api_key'   },
      },
    },
  }, null, 2);
}

function _buildParameters(searchParams, headers, redacted = false) {
  const params = [];
  const SKIP_H = new Set(['host','content-length','connection','accept-encoding','accept','user-agent']);
  const SENSITIVE = /authorization|cookie|token|secret|api[-_]?key|password|credential|signature|session/i;
  searchParams.forEach((value, name) => {
    params.push({ name, in: 'query', schema: { type: 'string', ...((redacted && /token|key|secret|auth|sig|pass|credential|session/i.test(name)) ? {} : { example: value }) } });
  });
  for (const [name] of Object.entries(headers)) {
    if (!SKIP_H.has(name.toLowerCase())) {
      params.push({ name, in: 'header', schema: { type: 'string', ...(redacted && SENSITIVE.test(name) ? {} : {}) } });
    }
  }
  return params;
}

// ─── Postman Collection v2.1 ─────────────────────────────────────────────────

export function exportPostman(captures, redacted = false) {
  return JSON.stringify({
    info: {
      _postman_id: randomUUID(),
      name:        'API Extraction Engine — Captures',
      description: 'Captured by API Extraction Engine',
      schema:      'https://schema.getpostman.com/json/collection/v2.1.0/collection.json',
    },
    item:     captures.map(c => _captureToPostmanItem(c, redacted)),
    variable: [],
    event:    [],
  }, null, 2);
}

function _captureToPostmanItem(c, redacted) {
  let u;
  try { u = new URL(c.url); } catch { u = null; }
  const method = c.method || 'GET';

  return {
    name:    `${method} ${u ? u.pathname : c.url}`,
    request: {
      method,
      header: Object.entries(c.requestHeaders || {}).map(([key, value]) => ({
        key,
        value: redacted && SENSITIVE_HEADERS.has(key.toLowerCase()) ? '{{REDACTED}}' : value,
        type:  'text',
      })),
      url: u ? {
        raw:      redacted ? _redactURL(c.url) : c.url,
        protocol: u.protocol.replace(':', ''),
        host:     u.hostname.split('.'),
        path:     u.pathname.split('/').filter(Boolean),
        query:    Array.from(u.searchParams.entries()).map(([key, value]) => ({
          key,
          value: redacted && /token|key|secret|auth|sig|pass|credential|session/i.test(key) ? '{{REDACTED}}' : value,
        })),
        port:     u.port || undefined,
      } : { raw: c.url },
      body: c.requestBody && c.requestBody !== '[empty]' && !['GET','HEAD'].includes(method) ? {
        mode:    'raw',
        raw:     redacted ? '[REDACTED]' : c.requestBody,
        options: { raw: { language: _guessLang(c.requestHeaders) } },
      } : undefined,
    },
    response: [{
      name:   `${c.responseStatus || 0} ${c.responseStatusText || ''}`,
      code:   c.responseStatus || 0,
      status: c.responseStatusText || '',
      header: Object.entries(c.responseHeaders || {}).map(([key, value]) => ({ key, value: redacted && SENSITIVE_HEADERS.has(key.toLowerCase()) ? '{{REDACTED}}' : value })),
      body:   redacted ? '[REDACTED]' : (c.responseBody || ''),
      _postman_previewlanguage: _guessLang(c.responseHeaders),
    }],
  };
}

function _guessLang(headers = {}) {
  const ct = headers['content-type'] || headers['Content-Type'] || '';
  if (ct.includes('json')) return 'json';
  if (ct.includes('xml'))  return 'xml';
  if (ct.includes('html')) return 'html';
  return 'text';
}

// ─── API Discovery Report ──────────────────────────────────────────────────────

export function exportDiscoveryReport(endpoints, graphqlOps = [], host = '') {
  const safeEndpoints = (Array.isArray(endpoints) ? endpoints : []).map(ep => ({
    url: _redactURL(ep.url || ''),
    host: ep.host || host || '',
    type: ep.type || 'candidate',
    source: ep.source || 'unknown',
    discoveryMethod: ep.discoveryMethod || ep.type || 'static_source',
    confidence: Number.isFinite(ep.confidence) ? ep.confidence : 45,
    confidenceLabel: ep.confidenceLabel || 'low',
    observed: ep.observed === true,
    evidence: ep.evidence || ep.type || 'candidate',
    evidenceSources: Array.isArray(ep.evidenceSources) ? ep.evidenceSources.slice(0, 12) : [],
    timestamp: ep.timestamp || null,
  }));
  const safeGraphQL = (Array.isArray(graphqlOps) ? graphqlOps : []).map(op => ({
    type: op.type || 'unknown',
    name: op.name || 'anonymous',
    // Deliberately omit full query source: it may contain private schema details or literals.
  }));
  return JSON.stringify({
    schemaVersion: 1,
    generator: 'API Extraction Engine',
    generatedAt: new Date().toISOString(),
    host,
    summary: {
      endpointCandidates: safeEndpoints.length,
      observedEndpoints: safeEndpoints.filter(ep => ep.observed).length,
      highConfidence: safeEndpoints.filter(ep => ep.confidence >= 80).length,
      graphqlOperations: safeGraphQL.length,
    },
    endpoints: safeEndpoints,
    graphqlOperations: safeGraphQL,
  }, null, 2);
}

// ─── Credential JSON ──────────────────────────────────────────────────────────

export function exportCredentialsJSON(credentials, redacted = false) {
  const out = credentials.map(c => redacted
    ? { type: c.type, hash: c.hash, id: c.id, sourceURL: c.sourceURL, timestamp: c.timestamp, expiry: c.expiry }
    : c
  );
  return JSON.stringify(out, null, 2);
}

// ─── Credential .env ──────────────────────────────────────────────────────────

export function exportCredentialsEnv(credentials, redacted = false) {
  const lines = [
    '# API Extraction Engine — Extracted Credentials',
    `# Generated: ${new Date().toISOString()}`,
    '# WARNING: This file contains sensitive material. Handle accordingly.',
    '',
  ];
  const seen = new Set();
  for (const c of credentials) {
    const key = `AGE_${c.type.toUpperCase().replace(/[^A-Z0-9]/g,'_')}_${c.hash.slice(0,8).toUpperCase()}`;
    if (seen.has(key)) continue;
    seen.add(key);
    lines.push(`# type=${c.type} source=${c.sourceURL} ts=${new Date(c.timestamp).toISOString()}`);
    if (c.expiry) lines.push(`# expires=${new Date(c.expiry).toISOString()}`);
    lines.push(`${key}=${redacted ? '[REDACTED]' : c.value}`);
    if (!redacted && c.type === 'jwt' && c.metadata?.decoded?.payload) {
      lines.push(`${key}_PAYLOAD=${JSON.stringify(c.metadata.decoded.payload)}`);
    }
    lines.push('');
  }
  return lines.join('\n');
}

// ─── GraphQL SDL ──────────────────────────────────────────────────────────────

export function exportGraphQLSDL(schema) {
  if (!schema) return '# No GraphQL schema captured\n';

  const BUILTIN = new Set([
    'String','Int','Float','Boolean','ID',
    '__Schema','__Type','__Field','__InputValue','__EnumValue','__Directive','__DirectiveLocation',
  ]);

  const typeMap = {};
  for (const t of (schema.types || [])) {
    if (!BUILTIN.has(t.name)) typeMap[t.name] = t;
  }

  const lines = ['# GraphQL Schema extracted by API Extraction Engine', ''];
  const emit  = name => {
    const t = typeMap[name];
    if (t) lines.push(..._typeToSDL(t));
  };

  if (schema.queryType?.name)        emit(schema.queryType.name);
  if (schema.mutationType?.name)     emit(schema.mutationType.name);
  if (schema.subscriptionType?.name) emit(schema.subscriptionType.name);

  const emitted = new Set([
    schema.queryType?.name,
    schema.mutationType?.name,
    schema.subscriptionType?.name,
  ]);
  for (const name of Object.keys(typeMap)) {
    if (!emitted.has(name)) lines.push(..._typeToSDL(typeMap[name]));
  }

  return lines.join('\n');
}

function _typeToSDL(t) {
  const lines = [];
  if (t.description) lines.push(`"""${t.description}"""`);
  switch (t.kind) {
    case 'OBJECT':
    case 'INTERFACE': {
      const kw   = t.kind === 'OBJECT' ? 'type' : 'interface';
      const impl = t.interfaces?.length ? ` implements ${t.interfaces.map(i => i.name).join(' & ')}` : '';
      lines.push(`${kw} ${t.name}${impl} {`);
      for (const f of (t.fields || [])) {
        if (f.description) lines.push(`  """${f.description}"""`);
        const args       = f.args?.length
          ? `(${f.args.map(a => `${a.name}: ${_ref(a.type)}`).join(', ')})`
          : '';
        const deprecated = f.isDeprecated ? ` @deprecated(reason: "${f.deprecationReason}")` : '';
        lines.push(`  ${f.name}${args}: ${_ref(f.type)}${deprecated}`);
      }
      lines.push('}', '');
      break;
    }
    case 'INPUT_OBJECT': {
      lines.push(`input ${t.name} {`);
      for (const f of (t.inputFields || [])) lines.push(`  ${f.name}: ${_ref(f.type)}`);
      lines.push('}', '');
      break;
    }
    case 'ENUM': {
      lines.push(`enum ${t.name} {`);
      for (const v of (t.enumValues || [])) lines.push(`  ${v.name}`);
      lines.push('}', '');
      break;
    }
    case 'SCALAR': {
      lines.push(`scalar ${t.name}`, '');
      break;
    }
    case 'UNION': {
      const types = t.possibleTypes?.map(pt => pt.name).join(' | ') || '';
      lines.push(`union ${t.name} = ${types}`, '');
      break;
    }
  }
  return lines;
}

function _ref(r) {
  if (!r) return 'String';
  if (r.kind === 'NON_NULL') return `${_ref(r.ofType)}!`;
  if (r.kind === 'LIST')     return `[${_ref(r.ofType)}]`;
  return r.name || 'String';
}

// ─── Download Trigger ─────────────────────────────────────────────────────────

export function downloadFile(content, filename, mimeType = 'application/json') {
  const blob = new Blob([content], { type: mimeType });
  const url  = URL.createObjectURL(blob);
  chrome.downloads.download({ url, filename, saveAs: false }, () => {
    setTimeout(() => URL.revokeObjectURL(url), 60000);
  });
}
