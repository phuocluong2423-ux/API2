# Security and Network Scope

API Discovery Engine (AGE) is a local browser extension for observing web application traffic and discovering API candidates in resources available to the active browser page.

## What AGE does not do

- No Dark Web or Deep Web crawling.
- No integration with breach dumps, stolen-credential feeds, credential marketplaces, or third-party threat-intelligence lookup APIs.
- No AGE-hosted collection server, cloud sync service, analytics, or usage telemetry in this repository's runtime code.
- No remote font download is required by the extension UI; fonts use locally available system fallbacks.

## Network activity that is part of the product

- Runtime hooks observe supported requests made by the web page and its JavaScript. Those page requests can naturally go to the application's API hosts or other domains used by that page.
- Static analysis may fetch JavaScript and source maps referenced by the active page. A site may serve these resources from a CDN.
- The optional Prober is disabled by default; enabling it sends requests to candidate endpoints.
- Replay sends a request to the destination shown in the replay options. Depending on options, request data and cookies may be included. Review the destination and data before replaying.

These behaviors are not Dark Web data collection, but they do involve normal network communication with the target application or resources it references. To test only a system you own, use a local/staging environment, keep Prober disabled unless needed, and review replay destinations.

## Local data and exports

Captures, endpoint metadata, and credential-like matches are stored in browser-local storage/IndexedDB; exports are downloaded locally. Treat them as sensitive because they may contain tokens, cookies, personal information, or internal URLs. Redaction is best-effort; inspect files before sharing them.

## Limits

AGE cannot discover a secret that exists only in a private leak forum, a breach archive, or another dataset that the active page and browser do not expose. Finding an endpoint also does not imply authorization to call it or access its data.
