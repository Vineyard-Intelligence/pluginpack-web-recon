# Web Recon

A Vineyard **plugin pack** that collects fingerprints from web pages — reusable **pivot
primitives** for clustering related infrastructure. One install, three plugins:

| Plugin | What it does | Produces |
|---|---|---|
| **Favicon Hash** (`run.vineyard.plugins.favicon_hash`) | Fetches the selected URL's favicon, computes the MurmurHash3 (MMH3) hash | `web.favicon_hash` node |
| **HTTP Header Hash** (`run.vineyard.plugins.hhhash`) | Fetches response headers (HEAD), hashes the ordered header-**name** structure (HHHash) | `web.hhhash` node |
| **DOM Structure Hash** (`run.vineyard.plugins.dom_hash`) | Fetches the HTML, hashes the ordered tag sequence (dom-hash, SHA-256 truncated to 32) | `web.dom_hash` node |

Each creates its node linked to the source `web.url` (edges `has favicon` /
`has header hash` / `has dom hash`).

## Why fingerprints matter

Adversaries rotate what they consider "indicators" — domains, IPs, certificates — but
rarely touch what they consider design assets:

- **Favicons** are reused verbatim across phishing kits, scam portals and darknet
  storefronts (MMH3 is Shodan's hash — repeatability, not uniqueness, is the goal).
- **Header structure** reflects the server stack (web server, reverse proxy, framework
  defaults) — the same HHHash means the same deployment practice.
- **DOM structure** survives text/branding/language changes — the same template means
  the same kit.

A shared fingerprint across otherwise unrelated hosts is a high-value pivot: Tor ↔
clear-web, staging ↔ production, clone ↔ original.

## Desktop only

All three targets are **dynamic** (the selected site) and cross-origin bodies/headers
require CORS, which most hosts do not send. They run through `ctx.net.probe` — the
desktop shell's anonymous, SSRF-guarded, redirect-free main-process fetch. In the web
build the plugins say so rather than half-working.

## Layout

- `src/main.ts` — pack entry: bundles the three plugins with `definePluginPack`.
- `src/favicon-hash.ts` / `src/hhhash.ts` / `src/dom-hash.ts` — the three plugins.
- `src/sdk.ts` — the Vineyard plugin SDK types, copied from the app repo so this pack
  builds standalone.
- `build.mjs` — esbuild bundler: `npm run build` → `dist/pack.mjs`.
- `plugins/web-recon.manifest.json` — the pack manifest (catalog entry source).

## License

Apache-2.0
