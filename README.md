# API Extraction Engine (AGE)

> A Chrome / Firefox MV3 browser extension that discovers, captures, classifies, and replays every API a web application uses — including hidden endpoints, GraphQL operations, WebSocket channels, and all credential material the browser holds.

---

## Install (unpacked)

### Chrome / Chromium
1. Clone or download this directory.
2. Open `chrome://extensions`.
3. Enable **Developer mode** (top-right toggle).
4. Click **Load unpacked** → select the `api-extraction-engine/` folder.
5. Pin the extension. The AGE icon appears in the toolbar.

### Firefox (MV3)
1. Copy `manifest.firefox.json` to `manifest.json` (overwrite).
2. Open `about:debugging#/runtime/this-firefox`.
3. Click **Load Temporary Add-on** → select `manifest.json`.

> **Note:** Firefox MV3 `world: "MAIN"` support requires Firefox 128+. On older versions the runtime hooks will not be injected; the static analyzer and bridge will still work.

---

## Permissions Rationale

| Permission | Reason |
|---|---|
| `<all_urls>` host permission | Required for the background service worker to make cross-origin requests (prober, replay) and for the content scripts to run on all pages |
| `cookies` | Background access to HttpOnly cookies not visible to `document.cookie`; cookie injection into replays |
| `scripting` | `registerContentScripts` to inject MAIN-world hooks and the static analyzer |
| `storage` | Hot ring buffer (chrome.storage.local) and working state (chrome.storage.session) |
| `downloads` | Export files via `URL.createObjectURL` + `chrome.downloads.download` |
| `sidePanel` | Persistent side panel UI (Chrome 114+) |
| `nativeMessaging` | Optional curl_cffi sidecar integration point (see §TLS Fingerprinting) |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  PAGE (MAIN world)                                              │
│  inject/hooks.js     — fetch/XHR/WS/SSE/beacon hooks           │
│  inject/analyzer.js  — script/sourcemap/storage/DOM analyzer   │
│         │  postMessage (random per-session channel)             │
├─────────┼───────────────────────────────────────────────────────┤
│  content/bridge.js (isolated world)                             │
│         │  chrome.runtime.sendMessage                           │
├─────────┼───────────────────────────────────────────────────────┤
│  background/service-worker.js                                   │
│  ├── storage.js          hot buffer + IndexedDB cold archive    │
│  ├── credential-extractor.js  JWT/key/cloud/signing extraction  │
│  ├── prober.js           HEAD/OPTIONS prober (CORS-free)        │
│  ├── replay.js           request replay + token chaining        │
│  └── exporter.js         HAR / OpenAPI / Postman / SDL / .env  │
├─────────────────────────────────────────────────────────────────┤
│  popup/popup.html + popup.js  — tabbed UI, replay, exports      │
│  sidepanel/sidepanel.html     — persistent panel variant        │
└─────────────────────────────────────────────────────────────────┘
```

### Channel Security

The MAIN-world scripts (`hooks.js`, `analyzer.js`) each generate a cryptographically random channel string at load time. They announce it via `postMessage({ type:'AGE_INIT', channel })`. The isolated-world bridge collects accepted channels into a `Set` and rejects any `postMessage` that does not carry an accepted channel. This prevents trivial interception by hostile page JavaScript.

---

## Module Reference

### 2.1 Runtime Interceptors (`inject/hooks.js`, MAIN world)
- `window.fetch` — full request/response capture including body clone
- `XMLHttpRequest` — open/setRequestHeader/send hooks + load/error listeners
- `WebSocket` — URL, subprotocols, first 50 frames in each direction
- `EventSource` — URL, first 100 SSE payloads
- `navigator.sendBeacon` — URL + body
- `Response.prototype.json` / `.text` — passthrough (fetch hook handles cloning)

**Service-worker limitation:** Service-worker `fetch` events (respondWith) intercept requests before they reach the network. These cannot be hooked from the page world or isolated world. Mitigation: enable *Bypass for network* in DevTools → Application → Service Workers, or install AGE before the target SW is activated.

### 2.2 Static Source Analyzer (`inject/analyzer.js`, MAIN world)
Runs at `document_idle`, re-runs on SPA navigation. Scans:
- Every `<script src>` and inline `<script>` (fetched fresh, not DOM `.textContent`)
- Source maps: fetches `//# sourceMappingURL=` targets, analyzes `sourcesContent[]`
- `localStorage`, `sessionStorage`, `window.*` globals (see `STATE_GLOBALS` in `shared/constants.js`)
- `<meta>` content, `<link>` prefetch hints, HTML comments
- `caches.keys()` Cache Storage manifests

Extracts: absolute URLs, path literals, route-map keys, versioned prefixes, GraphQL operations (named + gql`` tagged), foreign hostnames.

### 2.3 Live Endpoint Prober (`background/prober.js`)
Off by default. Enable via popup toggle or settings. Runs in background context — **not subject to page CORS**.
- HEAD with OPTIONS fallback
- GraphQL introspection + type enumeration fallback
- Discovery pass: 21 well-known paths per origin
- Rate-limited (default 250 ms)
- Destructive path skip (unless Aggressive Mode enabled)

### 2.4 Credential Extractor (`background/credential-extractor.js`)
Extracts and deduplicates (SHA-256) from every capture and storage scan:
- JWTs (decode header + payload, derive expiry from `exp`)
- `Authorization: Bearer` / `Basic` (base64-decoded)
- `Cookie` header (session cookies, JWT cookies)
- HttpOnly cookies via `chrome.cookies.getAll` (background-only)
- API keys in query params and headers matching `CREDENTIAL_KEY_RE`
- OAuth tokens, refresh tokens, PKCE verifiers
- AWS / GCP / Azure / Slack / GitHub / Stripe / SendGrid patterns
- Signing headers (`X-Signature`, `X-HMAC`, etc.) with note for offline algorithm recovery

### 2.5 Replay Engine (`background/replay.js`)
- Re-aims at alternate host (staging, attacker-controlled mirror)
- Variable substitution: `{{token}}`, `{{cookie:name}}`, `{{jwt}}`, `{{random_uuid}}`, `{{timestamp}}`
- Fresh cookie injection via `chrome.cookies.getAll`
- Token chaining: tokens in replay responses auto-stored for subsequent replays
- Fingerprint risk detection: Cloudflare, anti-bot tokens, HMAC signing headers
- Diff: status and body change logged against original capture

### 2.6 Export Module (`background/exporter.js`)
All exports are local `Blob` downloads — no server, no telemetry.
- **HAR 1.2** — importable into Burp Suite, Charles, DevTools, Insomnia
- **OpenAPI 3.1** — with both live-captured and static-discovered endpoints
- **Postman Collection v2.1**
- **Credential JSON** — full structured credential array
- **Credential .env** — `KEY=value` flat format with JWT payload expansion
- **GraphQL SDL** — reconstructed from introspection schema

### 2.7 Anonymity Layer (`background/prober.js`, `background/replay.js`)
- `ANON_STRIP_HEADERS` list: `Referer`, `Origin`, `Sec-Fetch-*`, `User-Agent`, `Cookie` stripped by default from prober requests
- Optional proxy relay: paste HTTP/SOCKS5 URL in Settings → all extension requests route through it
- User-agent rotation: newline-separated list, round-robins per request
- No analytics, no update pings, no remote config, no telemetry anywhere in this codebase

---

## TLS Fingerprinting

Certain endpoints use server-side TLS fingerprinting (JA3/JA4) to reject clients whose TLS handshake does not match expected browser fingerprints. The extension's background `fetch()` uses the browser's own TLS stack and **should** match a normal Chrome fingerprint. However:

- Cloudflare Bot Management, DataDome, PerimeterX, and similar products may still fingerprint at the HTTP/2 frame level or via JavaScript challenges.
- When AGE detects Cloudflare headers, anti-bot tokens, or signing headers in a capture, the Replay panel shows a **Fingerprint Warning** explaining the risk.
- **Integration point for curl_cffi sidecar:** In `background/replay.js`, replace the `fetch()` call inside `replayRequest()` with a `chrome.runtime.sendNativeMessage('age_sidecar', ...)` call to a local Python process running `curl_cffi`. The native host manifest and Python script are out of scope for this extension but the hook location is clearly marked.

---

## Known Limitations

| Limitation | Notes |
|---|---|
| Service-worker intercepted requests | Cannot be hooked from page world. Enable "Bypass for network" in DevTools as a workaround. |
| HTTP/2 PUSH frames | Not observable from the extension. |
| WebTransport / WebRTC data channels | Not yet hooked. See §How to Extend. |
| gRPC-Web | Appears as `fetch` POST to a gRPC endpoint. Body is binary protobuf — captured as binary blob. |
| Proxy support | Extension uses browser `fetch()`. True SOCKS5 proxying requires OS-level routing or the curl_cffi sidecar. |
| Firefox MAIN world | Requires Firefox 128+. |

---

## How to Extend

### Adding a New Hook Type (e.g. WebTransport, WebRTC DataChannel)

1. Open `inject/hooks.js`.
2. At the bottom of the IIFE, add your hook following the same pattern:
   ```js
   const _OrigWT = globalThis.WebTransport;
   function _HookedWT(url, opts) {
     const wt = new _OrigWT(url, opts);
     _send('CAPTURE', { type: 'webtransport', url, timestamp: Date.now() });
     // hook wt.createBidirectionalStream(), datagrams.readable, etc.
     return wt;
   }
   globalThis.WebTransport = _HookedWT;
   ```
3. Add a `wt` classification case in `background/service-worker.js → _classifyCapture()`.

### Adding a New Discovery Source (e.g. mobile APK endpoint references)

1. Add your extractor function to `inject/analyzer.js` (or a new `inject/apk-analyzer.js`).
2. Register the new file in `background/service-worker.js → _registerContentScripts()`.
3. The extracted endpoints flow through the same `ANALYSIS_RESULT` message path and land in IndexedDB automatically.

### Adding a New Export Format

1. Add your serializer function to `background/exporter.js`.
2. Add a `case 'your_format':` branch in `background/service-worker.js → _doExport()`.
3. Add an export button in `popup/popup.html` and wire it in `popup/popup.js`.

---

*API Extraction Engine — client-side observation only. No credential exfiltration to any remote host. No tracking. No analytics.*
