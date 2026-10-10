<div align="center">

# API Extraction Engine

**Discover API candidates. Observe browser traffic. Organize evidence. Export useful documentation.**

A browser extension for developers and security testers who need to understand the API surface of a web application they own or are authorized to assess.

**Manifest V3** · **Chrome/Chromium** · **Firefox configuration** · **JavaScript**

[Features](#features) · [Install](#installation) · [Quick start](#quick-start) · [Architecture](#architecture) · [Security](#security-and-privacy) · [Limitations](#limitations)

</div>

---

## Overview

API Extraction Engine (AGE) combines **runtime observation** with **static source analysis** to build a searchable inventory of API-related endpoints and GraphQL operations.

AGE is designed to help answer:

- Which endpoints did this application actually call?
- Which API paths or service hosts are referenced in its loaded JavaScript?
- Where did a candidate come from, and what evidence supports it?
- What can be documented from captured requests and responses?
- How did the observed API surface change during a testing session?

> **Important:** Discovery is best-effort. AGE cannot guarantee that it will find every endpoint, and a candidate found in source code is not proof that the endpoint exists or is accessible. Use active probing and request replay only against systems you own or have explicit permission to test.

## Features

### Runtime traffic observation

AGE instruments selected browser APIs in the page's main world and records activity that passes through them:

- **fetch()** and **XMLHttpRequest**
- **WebSocket** connection metadata and a bounded number of frames
- **Server-Sent Events (EventSource)**
- **navigator.sendBeacon()**
- Request/response metadata and bodies, subject to capture limits

Requests handled entirely inside a service worker or through unsupported browser APIs may not appear in the capture list.

### Deep API discovery

The source analyzer combines several types of evidence:

- External and inline JavaScript references
- Available source maps and embedded source content
- API-like URL and path literals, versioned routes, base-URL configuration and route-map keys
- Named GraphQL operations and gql template strings
- Framework state/configuration globals and DOM hints
- Cache Storage entries and Performance Resource Timing clues
- Bounded rescans when a single-page application inserts new script bundles

Each discovered endpoint can include its source, discovery method, evidence, a heuristic confidence score and an observed flag. Confidence is a **ranking signal, not a calibrated probability**; inspect the evidence before drawing conclusions.

### Passive Deep Find site inventory

The **Deep Find** view builds a broader inventory from the active page and its already-referenced resources. It can summarize:

- Technology/framework clues inferred from known script paths, runtime markers and DOM signatures (heuristic; not a definitive fingerprint).
- Script, stylesheet, image, iframe, icon and web-app-manifest references, plus external origins seen in the page's resource list.
- Same-origin link routes and GraphQL operation names.
- Form actions, methods and input field names/types only. Deep Find does **not** record form input values in this profile.
- Local/session storage key names and approximate value lengths only. Storage values are omitted from the Deep Find profile.
- Structured-data types, selected page metadata, service-worker control hints, DOM data-attribute names and passive configuration-review signals such as HTTP resource references, external form actions, and external scripts without SRI.

Deep Find is passive: it does not crawl arbitrary paths, submit forms, brute-force routes, or perform reputation lookups. Findings are evidence-backed review hints, not confirmed vulnerabilities. Some observations concern the page or third-party assets it references; they are not Dark Web/Deep Web intelligence. Data is bounded and stored in the browser locally. Captures in the separate All/Auth/Secrets views retain their existing behavior, so treat those capture records as sensitive.

### Optional endpoint probing

The Prober is disabled by default. When enabled, the current implementation can:

- Try **HEAD**, with an **OPTIONS** fallback
- Check a curated set of common documentation and discovery paths
- Attempt GraphQL introspection and a lighter type-enumeration fallback
- Apply a configurable delay between probes and skip paths that match destructive-looking patterns unless Aggressive Mode is enabled

Probing creates real requests to the target. Review the target origin and selected mode before starting; keep aggressive checks off unless you have a controlled test environment.

### Request replay

The replay panel supports method, header and body overrides, variable substitution, optional cookie injection, alternate-host targeting, response comparison and token chaining.

Replay is powerful and can change server-side state. A replay sent to another host may carry sensitive request data or cookies depending on its options. Use a dedicated test account and a trusted test/staging target. Review the final destination and headers before sending.

### Export and reporting

AGE can generate local downloads in these formats:

| Format | Intended use |
| --- | --- |
| **HAR 1.2** | Inspect captured HTTP transactions in compatible tools |
| **OpenAPI 3.1** | Generate a draft description from captures and discovered paths |
| **Postman Collection 2.1** | Continue manual API exploration in Postman |
| **Discovery Report JSON** | Review endpoint candidates, source evidence, confidence and GraphQL operation names |
| **Deep Find JSON** | Export a broader passive site inventory: technology clues, resource references, routes, form field names, storage key names and review signals |
| **Credential JSON / .env** | Inventory credential-like values for an authorized assessment |
| **GraphQL SDL** | Export a schema when AGE has captured introspection data |

Generated documentation is a starting point, not a guaranteed-complete or production-ready API specification. Redaction is best-effort; inspect every export before sharing it.

## Installation

AGE is a source-based browser extension. There is no build step in the current repository.

### Chrome / Chromium

1. Download the repository ZIP from GitHub and extract it, or clone the repository.
2. Open **chrome://extensions**.
3. Enable **Developer mode**.
4. Select **Load unpacked**.
5. Choose the extracted repository root—the directory containing **manifest.json**.
6. Pin AGE to the toolbar if you want quick access.

### Firefox

1. Download or clone the repository.
2. In a separate working copy, copy **manifest.firefox.json** to **manifest.json**.
3. Open **about:debugging#/runtime/this-firefox**.
4. Select **Load Temporary Add-on** and choose that manifest.json.
5. Verify the extension on your installed Firefox version before using it for an assessment.

The Firefox manifest declares a minimum Gecko version of 128. Browser APIs and main-world injection support can differ between Firefox and Chromium; treat compatibility as something to verify, not assume.

### Updating

Download or pull the latest source, then use **Reload** on the extension's details card in the browser's extension manager. Revisit the page being tested after updating so content hooks are injected into a fresh page context.

## Quick start

1. **Install AGE** using the steps above.
2. **Open a test application** that you own or are authorized to assess.
3. **Browse normally.** Visit relevant routes and use the application's ordinary features; runtime requests are only observed when the application actually performs them.
4. **Open AGE** and review the capture list and discovered-endpoint view.
5. **Filter and inspect evidence.** Compare runtime observations with static candidates; do not assume every candidate is reachable.
6. **Review Deep Find.** Inspect technology clues, linked assets, routes, forms (field names only), storage key names and passive security review signals for the active page.
6. **Probe only when appropriate.** Confirm the target origin and keep the Prober disabled unless active checks are part of your authorized test plan.
7. **Export the report** you need. Review exports for tokens, cookies, personal data and internal URLs before sharing them.

For single-page applications, navigate through the app and allow AGE to observe newly loaded resources. A single initial page load is unlikely to reveal the full API surface.

## Understanding discovery results

Deep Find keeps a separate page inventory from the endpoint list. It includes page metadata, framework clues, referenced assets and hosts, link routes, form structure, storage key names, and heuristic review signals. The report deliberately excludes form input values and storage values. It does not crawl external sites or query breach-data sources.


| Evidence | What it means |
| --- | --- |
| **Runtime observed** | A matching resource was present in the page's performance resource timeline or captured through a supported runtime hook |
| **Static source** | An API-like URL or path was found in script text or a source map |
| **DOM / cache / state** | A URL clue was found in a document hint, cache entry or framework state |
| **Probed** | An active check was sent and a response was recorded |
| **GraphQL operation** | An operation-like definition was found in source; schema data is collected separately |

These categories are not interchangeable. A runtime resource entry does not necessarily prove that a request succeeded, and a static path does not prove that a server implements it. Confirm important findings in the request details and with a controlled test.

## Architecture

~~~mermaid
flowchart TB
    A["Target page<br/>Main world"] --> B["Runtime hooks<br/>fetch · XHR · WebSocket · SSE · beacon"]
    A --> C["Deep analyzer<br/>scripts · source maps · DOM · cache · resource timing"]
    B --> D["Content bridge<br/>observation messages only"]
    C --> D
    D --> E["Background service worker"]
    E --> F["Capture & endpoint storage<br/>browser storage + IndexedDB"]
    E --> G["Optional Prober & Replay"]
    E --> H["Exporters<br/>HAR · OpenAPI · Postman · JSON · SDL · env"]
    F --> I["Popup and side panel"]
    G --> I
    H --> J["Local downloaded files"]
~~~

### Source layout

| Path | Responsibility |
| --- | --- |
| **manifest.json** | Chromium extension manifest |
| **manifest.firefox.json** | Firefox-specific manifest configuration |
| **inject/hooks.js** | Runtime request and connection observation |
| **inject/analyzer.js** | Static source analysis, endpoint discovery and passive Deep Find inventory |
| **content/bridge.js** | Main-world observation bridge |
| **background/service-worker.js** | Message routing, coordination, probing, exports and lifecycle |
| **background/storage.js** | Local capture, endpoint and credential storage |
| **background/credential-extractor.js** | Detection and classification of credential-like material |
| **background/prober.js** | Optional endpoint and GraphQL checks |
| **background/replay.js** | Controlled request replay and response comparison |
| **background/exporter.js** | Local report and collection generation |
| **popup/** and **sidepanel/** | User interface |

## Network scope and external sources

AGE does **not** include a Dark Web/Deep Web crawler, breach-data feed, third-party credential marketplace integration, or external threat-intelligence lookup service. It does not send captures to an AGE-operated backend or include usage analytics/telemetry in this source tree. Captures, endpoint records and generated exports are stored locally in the browser or downloaded locally.

Be precise about what “local” means: AGE is a browser extension that inspects the page you open. The page itself may contact its own API hosts or third-party CDNs. Static analysis may fetch JavaScript or source maps referenced by that page (which can also be hosted on a CDN). Those are page resources, not a Dark Web intelligence source. When enabled, the Prober sends HTTP requests to candidate endpoints; Replay sends a request to the destination shown in its controls and may include captured data/cookies depending on options. Keep Prober off unless authorized, review replay destinations, and never replay captured credentials to a host you do not control or have permission to test.

The extension UI uses system fonts; it does not need to download Google Fonts to render. README images/badges are not needed for runtime operation.

## Security and privacy

AGE is a high-privilege development tool. It can inspect traffic on pages where it is active, and its credential-analysis features may encounter session tokens, API keys, cookies, personal data or private application content.

- **Use only on authorized targets.** Having an endpoint URL does not grant permission to access it.
- **Treat captured data as sensitive.** Review and delete captures when no longer needed. Do not commit raw captures, credential files or tokens to Git.
- **Check every replay destination.** Alternate-host replay and cookie injection can expose sensitive data if used against the wrong origin.
- **Prefer redacted exports.** Redaction is heuristic and may not catch every sensitive field; manually review files before sharing.
- **Understand permissions.** The all-URLs host permission is broad because AGE is designed to work on arbitrary test applications. Install only a version you trust.
- **Review untrusted endpoint evidence.** Page-origin data is treated as observation input, not authorization to run privileged extension commands. The bridge is restricted to ingestion message types; its per-page channel is not considered a secret.

AGE is designed around local browser storage and local downloads. The current source does not require an AGE-hosted backend to capture traffic or generate exports; still, audit the exact source you install and avoid using modified builds you do not trust.

### Permissions

| Permission | Purpose |
| --- | --- |
| **all-URLs host permission** | Run observation scripts and permit extension-context requests for supported probing and replay workflows |
| **cookies** | Read cookies for supported capture/replay workflows, including cookies inaccessible to page JavaScript |
| **scripting** | Register the main-world instrumentation scripts |
| **storage** | Persist settings and capture data in browser storage |
| **downloads** | Save generated reports and collections |
| **sidePanel** | Provide the persistent side panel in Chromium browsers that support it |
| **nativeMessaging** | Declared for a possible local integration point; a native sidecar is not bundled with this repository |

## Scope of discovery and leaked credentials

AGE is a browser-side API discovery tool, not a Dark Web search engine or a breach-data repository. It can only analyze resources, runtime observations and storage that are available in the active browser context. A key advertised for sale in a private forum or obtained from a separate breach will not become discoverable just by opening VirusTotal. Finding an endpoint also does not grant permission to call it.

This update improves discovery of request-call literals, framework route declarations, and common escaped URL separators in loaded source. Results remain heuristic candidates and should be checked against an authorized test environment. For exposure response, use your organization’s approved secret-scanning and threat-intelligence sources, rotate confirmed exposed keys, and do not validate or use credentials that do not belong to you.

## Current limitations

- Discovery is heuristic and bounded by source count, data-size limits, browser permissions and what the page loads.
- Server-only routes, unreferenced endpoints, feature-flagged code and endpoints hidden behind unvisited application flows may not be discovered.
- Service-worker-handled traffic, WebTransport, WebRTC data channels and some binary protocols are not fully instrumented.
- GraphQL operation text found in JavaScript is not the same as a captured schema; SDL export requires schema data.
- A successful HEAD or OPTIONS response is not proof that an endpoint's application-level operation works. Conversely, blocked probes do not prove that an endpoint is absent.
- OpenAPI output is inferred from observed data; parameter types, authentication rules, schemas and required fields may need manual correction.
- Proxy-related settings exist, but this extension does **not** provide a general-purpose HTTP/SOCKS5 tunnel for all browser-extension requests.
- The current source has not been validated across every supported Chrome and Firefox version. Test the exact browser and build you intend to use.

## Responsible testing

Use AGE on your own application, a deliberately vulnerable lab, a staging environment you control or another system for which you have explicit authorization. Keep active probing conservative, avoid actions that modify production data, and follow the target's testing rules.

This project is an inspection and testing aid—not a guarantee of security, completeness or permission.

## Contributing

Improvements that make AGE more accurate, safer and easier to audit are welcome.

1. Keep discovery evidence explainable: record where a candidate came from.
2. Bound scans and avoid unbounded work on large pages.
3. Keep privileged extension actions out of the untrusted page-message path.
4. Make redaction behavior explicit and test all export formats.
5. Document browser limitations and distinguish implemented behavior from future work.

Before submitting changes, test the extension on a controlled sample site, inspect the browser console for errors, and verify capture, discovery, replay and export flows affected by the change.

---

<div align="center">

**API Extraction Engine · Built for authorized API discovery and testing**

</div>
