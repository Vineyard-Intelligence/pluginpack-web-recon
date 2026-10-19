# Web Recon

A Vineyard **plugin pack** that collects fingerprints from web pages — reusable **pivot
primitives** for clustering related infrastructure. One install, three plugins:

| Plugin | What it does | Produces |
|---|---|---|
| **Favicon Hash** (`run.vineyard.plugins.favicon_hash`) | Fetches the selected URL's favicon and hashes it in every form the search services index (Shodan-style MMH3, its hex form, MD5, SHA-256, pHash, dHash) | `web.favicon_hash` node |
| **HTTP Header Hash** (`run.vineyard.plugins.hhhash`) | Requests the URL over HTTP/1.1 and hashes the ordered response header-**name** structure (HHHash) | `web.hhhash` node |
| **DOM Structure Hash** (`run.vineyard.plugins.dom_hash`) | Fetches the HTML, hashes the ordered tag sequence (dom-hash, SHA-256 truncated to 32) | `web.dom_hash` node |

Each creates its node linked to the source `web.url` (edges `has favicon` /
`has header hash` / `has dom hash`).

## Why fingerprints matter

Adversaries rotate what they consider "indicators" — domains, IPs, certificates — but
rarely touch what they consider design assets:

- **Favicons** are reused verbatim across phishing kits, scam portals and darknet
  storefronts. A common default icon (a framework's, a hosting panel's) is the exception: it
  matches unrelated sites.
- **Header structure** reflects the server stack (web server, reverse proxy, framework
  defaults) — the same HHHash means the same deployment practice.
- **DOM structure** survives text/branding/language changes — the same template means
  the same kit.

A shared fingerprint across otherwise unrelated hosts is a high-value pivot: Tor ↔
clear-web, staging ↔ production, clone ↔ original.

## Favicon hash forms

A favicon hash identifies the icon file a site serves. Every search service hashes the same file,
but not in the same form, so one `web.favicon_hash` node records each form under its own property:

| Property | Form | Search it on |
|---|---|---|
| `hash_value` | MurmurHash3 x86 32-bit (seed 0) of the file's base64, with a newline every 76 characters and at the end, as a signed decimal | Shodan `http.favicon.hash:<v>`, FOFA `icon_hash="<v>"`, Censys `host.services.endpoints.http.favicons.hash_shodan="<v>"`, ZoomEye `iconhash="<v>"` |
| `mmh3_hex` | `hash_value` in hex, sign kept (`-30149ea`) | Criminal IP `favicon: <v>` |
| `md5` | MD5 of the file's bytes, lowercase hex | Censys `…favicons.hash_md5="<v>"`, ZoomEye `iconhash="<v>"`, 360 Quake `favicon:"<v>"`, Hunter.how `favicon_hash=="<v>"`, ONYPHE `app.favicon.imagemd5:"<v>"`, VirusTotal `entity:url main_icon_md5:<v>` |
| `sha256` | SHA-256 of the file's bytes, lowercase hex | Censys `…favicons.hash_sha256="<v>"`, Netlas `http.favicon.hash_sha256:<v>`, urlscan.io `hash:<v>` |
| `phash` | pHash of the decoded image as the Python ImageHash library computes it: grayscale, Lanczos to 32×32, DCT, top-left 8×8 against their median | Censys indexes a 64-bit perceptual hash as `…favicons.hash_phash="<v>"` but does not document its algorithm, so a match is not established |
| `dhash` | Krawetz's dHash of the decoded image (grayscale, Lanczos to 9×8, one bit per adjacent pair) in the bit order VirusTotal's appears to use | VirusTotal `entity:url main_icon_dhash:<v>` (a similarity search) |

Censys keeps the same fields under `web.endpoints.http.favicons` for web properties, and hashes only
the first 384 KB of a favicon, so for a larger icon none of its hashes match these. The plugin fetches at
most 512 KB; a larger icon counts as a failed fetch.

`phash` and `dhash` are perceptual: they stay close when an icon is re-encoded, resized or slightly
edited, and two of them are compared by how many of their 64 bits differ (Krawetz counts 10 or fewer
as a likely variant), not by equality. Both start from the pixels Pillow decodes and Pillow's Lanczos
resize, reproduced bit for bit in `src/favicon-image.ts` and `src/perceptual-hash.ts`: ImageHash runs on
Pillow, and a browser decoder rounds transparent edges differently, which moves bits. For a multi-image
ICO the frame is Pillow's: the largest, and among equal sizes the one with the lowest colour depth. They
are computed for ICO, PNG and BMP icons, except 16-bit grayscale PNG, 16-bit and RLE BMP, icons over
2048 pixels a side, and files Pillow refuses.

`phash` also reproduces SciPy's DCT operation for operation. On a mirrored or smoothly shaded icon some
DCT coefficients are zero in exact arithmetic, and the rounding noise SciPy returns for them decides
their bits. That noise depends on the SciPy build: this matches SciPy up to 1.17 (pocketfft) on x86-64,
while SciPy 1.18 (ducc0) and arm64 builds can differ from it, and from each other, in those bits.

`dhash` follows Krawetz's difference hash in the form VirusTotal's `main_icon_dhash` appears to take.
VirusTotal does not document the algorithm; the icon dHash of SuperPeHasher and FileInsight-plugins
differs from Krawetz's in three ways, and this follows it: the 9×8 thumbnail is Pillow's Lanczos resize
(Krawetz scales his own way), a bit is set when the LEFT pixel is brighter, and each byte fills from its
lowest bit. With that packing Facebook's favicon comes within 2 bits of the value a third-party
VirusTotal query list ([repulsivityy/vt_dorks](https://github.com/repulsivityy/vt_dorks)) gives for it;
with Krawetz's own, 11. VirusTotal's documented example (Dropbox) could not be reproduced from current or
archived Dropbox icons.

Netlas's `perceptual_hash` is an aHash and is not computed.

`test-fixtures/make-favicons.py` writes the reference icons in `test-fixtures/favicons/` and Pillow and
ImageHash's values for them; `test-plugin.mjs` checks the plugin against those.

The plugin fetches `/favicon.ico` only: it does not read the page for a `<link rel="icon">`, and
does not follow a redirect.

## Desktop only

All three targets are **dynamic** (the selected site) and cross-origin bodies/headers
require CORS, which most hosts do not send. Requests are anonymous and do not follow
redirects. In the web build the plugins say so rather than half-working.

## Layout

- `src/main.ts` — pack entry: bundles the three plugins with `definePluginPack`.
- `src/favicon-hash.ts` / `src/hhhash.ts` / `src/dom-hash.ts` — the three plugins.
- `src/favicon-image.ts` / `src/perceptual-hash.ts` — Pillow-exact icon decoding and resize, pHash and dHash.
- `test-fixtures/` — reference icons and their Pillow/ImageHash values (`make-favicons.py`), checked by `test-plugin.mjs`.
- `src/sdk.ts` — the Vineyard plugin SDK types, copied from the app repo so this pack
  builds standalone.
- `build.mjs` — esbuild bundler: `npm run build` → `dist/pack.mjs`.
- `plugins/web-recon.manifest.json` — the pack manifest (catalog entry source).

## License

Apache-2.0
