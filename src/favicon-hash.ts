// Favicon Hash plugin — fetches a site's /favicon.ico, hashes it in every form the search services
// index, and creates a web.favicon_hash node linked to the source URL.
//
// The forms, checked against each service's documentation on 2026-10-19:
//   hash_value  Shodan's: MurmurHash3-32 (seed 0) of the favicon BASE64-ENCODED with a newline every 76
//               characters and one at the end (Python's base64.encodebytes), as a signed integer — not
//               of the raw bytes. Shodan http.favicon.hash, FOFA icon_hash, Censys favicons.hash_shodan,
//               ZoomEye iconhash. Checked against Python mmh3 on real favicons (google.com -> 708578229).
//   mmh3_hex    the same value in hex with its sign kept, which Criminal IP's favicon: filter takes.
//   md5         MD5 of the raw bytes: Censys hash_md5, ZoomEye iconhash, 360 Quake, Hunter.how, ONYPHE,
//               VirusTotal main_icon_md5.
//   sha256      SHA-256 of the raw bytes: Censys hash_sha256, Netlas, urlscan.io hash.
//   phash       ImageHash's pHash of the decoded image (perceptual-hash.ts). Censys indexes a 64-bit
//               perceptual hash as favicons.hash_phash without documenting its algorithm, so whether
//               this one matches it is not known.
//   dhash       Krawetz's dHash in the bit order VirusTotal's main_icon_dhash appears to use, which
//               VirusTotal searches by similarity. Both only for the icons favicon-image.ts decodes.
// Censys hashes only the first 384 KB of a favicon, so for a larger icon none of its hashes match the
// ones recorded here. An icon over MAX_FAVICON_BYTES arrives truncated and counts as a failed fetch.
// Netlas's perceptual_hash is an aHash and is not computed.
//
// The bytes come from the desktop probe as base64 (bodyEncoding), because a UTF-8 decode of a binary
// file is lossy.
import { definePlugin } from './sdk';
import type { HostContext, RunResult, GraphNode } from './sdk';
import { findExisting } from './dedup';
import { decodeFavicon } from './favicon-image';
import { dhashHex, phashHex } from './perceptual-hash';

// ---- MurmurHash3 x86 32-bit (pure JS, no deps) ----
function murmur3_32(key: Uint8Array, seed: number = 0): number {
    const len = key.length;
    const c1 = 0xcc9e2d51;
    const c2 = 0x1b873593;
    let h1 = seed >>> 0;
    let roundedEnd = (len & ~0x3) >>> 0;

    for (let i = 0; i < roundedEnd; i += 4) {
        let k1 = (key[i] | (key[i + 1] << 8) | (key[i + 2] << 16) | (key[i + 3] << 24)) >>> 0;
        k1 = Math.imul(k1, c1);
        k1 = (k1 << 15) | (k1 >>> 17);
        k1 = Math.imul(k1, c2);
        h1 ^= k1;
        h1 = (h1 << 13) | (h1 >>> 19);
        h1 = (Math.imul(h1, 5) + 0xe6546b64) >>> 0;
    }

    let k2 = 0;
    const tail = len & 0x3;
    if (tail === 3) k2 ^= key[roundedEnd + 2] << 16;
    if (tail >= 2) k2 ^= key[roundedEnd + 1] << 8;
    if (tail >= 1) {
        k2 ^= key[roundedEnd];
        k2 = Math.imul(k2, c1);
        k2 = (k2 << 15) | (k2 >>> 17);
        k2 = Math.imul(k2, c2);
        h1 ^= k2;
    }

    h1 ^= len;
    h1 ^= h1 >>> 16;
    h1 = Math.imul(h1, 0x85ebca6b) >>> 0;
    h1 ^= h1 >>> 13;
    h1 = Math.imul(h1, 0xc2b2ae35) >>> 0;
    h1 ^= h1 >>> 16;
    return h1 >>> 0;
}

/** Signed decimal form (Shodan-style: negative when the high bit is set). */
function shodanForm(h: number): number {
    return h > 0x7fffffff ? h - 0x100000000 : h;
}

/** Shodan's favicon hash of base64 content: MMH3 over base64 wrapped at 76 columns, trailing newline. */
export function shodanFaviconHash(base64: string): number {
    const wrapped = (base64.match(/.{1,76}/g) ?? []).map((line) => `${line}\n`).join('');
    return shodanForm(murmur3_32(new TextEncoder().encode(wrapped), 0));
}

/** The favicon's own bytes, which the digest forms hash (Shodan's form hashes the base64 text). */
function base64ToBytes(base64: string): Uint8Array<ArrayBuffer> {
    const bin = atob(base64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}

const hex = (bytes: Uint8Array): string => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

// ---- MD5 (RFC 1321, pure JS: WebCrypto has no MD5) ----
const MD5_SHIFT = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15,
    21,
];
const MD5_K = Array.from({ length: 64 }, (_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32) >>> 0);

/** MD5 of raw bytes as lowercase hex. */
export function md5Hex(bytes: Uint8Array): string {
    const len = bytes.length;
    // The message, a 0x80 byte, zeros, then the bit length as 64-bit little-endian, to a multiple of 64.
    const padded = new Uint8Array((((len + 8) >> 6) + 1) << 6);
    padded.set(bytes);
    padded[len] = 0x80;
    const view = new DataView(padded.buffer);
    view.setUint32(padded.length - 8, (len * 8) >>> 0, true);
    view.setUint32(padded.length - 4, Math.floor((len * 8) / 2 ** 32) >>> 0, true);

    let a0 = 0x67452301;
    let b0 = 0xefcdab89;
    let c0 = 0x98badcfe;
    let d0 = 0x10325476;
    for (let off = 0; off < padded.length; off += 64) {
        let a = a0;
        let b = b0;
        let c = c0;
        let d = d0;
        for (let i = 0; i < 64; i++) {
            let f: number;
            let g: number;
            if (i < 16) {
                f = (b & c) | (~b & d);
                g = i;
            } else if (i < 32) {
                f = (d & b) | (~d & c);
                g = (5 * i + 1) % 16;
            } else if (i < 48) {
                f = b ^ c ^ d;
                g = (3 * i + 5) % 16;
            } else {
                f = c ^ (b | ~d);
                g = (7 * i) % 16;
            }
            f = (f + a + MD5_K[i] + view.getUint32(off + g * 4, true)) | 0;
            a = d;
            d = c;
            c = b;
            b = (b + ((f << MD5_SHIFT[i]) | (f >>> (32 - MD5_SHIFT[i])))) | 0;
        }
        a0 = (a0 + a) | 0;
        b0 = (b0 + b) | 0;
        c0 = (c0 + c) | 0;
        d0 = (d0 + d) | 0;
    }
    const out = new DataView(new ArrayBuffer(16));
    [a0, b0, c0, d0].forEach((w, i) => out.setUint32(i * 4, w, true));
    return hex(new Uint8Array(out.buffer));
}

/** SHA-256 of raw bytes as lowercase hex. */
async function sha256Hex(bytes: Uint8Array<ArrayBuffer>): Promise<string> {
    return hex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));
}

/** Extract the URL of a web.url node; null if malformed. */
function urlOf(seed: GraphNode): string | null {
    const u = typeof seed.data?.url === 'string' ? seed.data.url : '';
    if (!u) return null;
    try {
        new URL(u);
        return u;
    } catch {
        return null;
    }
}

/** Best-guess favicon location: /favicon.ico (we do not fetch the page to find a <link>). */
function faviconUrl(pageUrl: string): string {
    try {
        const u = new URL(pageUrl);
        u.pathname = '/favicon.ico';
        u.search = '';
        u.hash = '';
        return u.toString();
    } catch {
        return pageUrl;
    }
}

const MAX_FAVICON_BYTES = 512 * 1024; // favicons are tiny; this is generous

// One plain sentence per form; the registry caps a description at 1024 characters.
const FAVICON_DESCRIPTION =
    'Fetches /favicon.ico from the host of each selected URL and creates a web.favicon_hash node linked by "has favicon". ' +
    'A favicon hash identifies the icon file a site serves, and each form a search service indexes is its own property. ' +
    'hash_value is the Shodan-style MurmurHash3 searched by Shodan http.favicon.hash, FOFA icon_hash, Censys favicons.hash_shodan and ZoomEye iconhash. ' +
    'mmh3_hex is that value in hex, searched by Criminal IP favicon:. ' +
    'md5 is searched by Censys favicons.hash_md5, ZoomEye iconhash, 360 Quake favicon, Hunter.how favicon_hash, ONYPHE app.favicon.imagemd5 and VirusTotal main_icon_md5. ' +
    'sha256 is searched by Censys favicons.hash_sha256, Netlas http.favicon.hash_sha256 and urlscan.io hash. ' +
    'phash and dhash are perceptual hashes of ICO, PNG and BMP icons, compared by how many of their 64 bits differ. ' +
    'phash is the ImageHash pHash. ' +
    'dhash follows VirusTotal main_icon_dhash, which VirusTotal searches by similarity. ' +
    'Does not follow redirects or read the page for a <link rel="icon">. Desktop only.';

export const faviconHash = definePlugin({
    manifest: {
        identifier: 'run.vineyard.plugins.favicon_hash',
        content_type: 'vineyard:plugin',
        name: 'Favicon Hash',
        version: '1.3.0',
        description: FAVICON_DESCRIPTION,
        icon: 'image',
        author: { name: 'VINEYARD', url: 'https://vineyard.run' },
        license: 'Apache-2.0',
        platforms: {
            primary: 'desktop',
            web: { runtime: 'sandbox-js', entry: 'dist/pack.mjs' },
            desktop: { runtime: 'sandbox-js', entry: 'dist/pack.mjs' },
        },
        io: {
            consumes: [
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'web', name: 'url' },
            ],
            produces: [
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'web', name: 'favicon_hash' },
            ],
        },
        scopes: {
            graph: ['node:read', 'node:create', 'edge:create'],
            web_probe: {
                purpose: 'Fetch the favicon of each selected site.',
            },
        },
        lifecycle: { persistence: 'opt-in', controls: ['progress', 'cancel'], progress: 'determinate' },
    },

    async run(ctx: HostContext): Promise<RunResult> {
        const ids = ctx.input.selection;
        if (!ids.length) return { summary: 'Select a URL node first', counts: { created: 0 } };
        if (!ctx.net?.probe) {
            return {
                summary:
                    'Favicon hashing needs the desktop shell (the target is dynamic and favicons are usually served without CORS headers). Run this plugin in the desktop app.',
                counts: { created: 0 },
            };
        }

        let created = 0;
        let reused = 0;
        let noUrl = 0;
        let notFound = 0;
        let failed = 0;
        let noImage = 0;
        let lastHash = '';
        let lastBytes = 0;
        let lastReused = false;
        for (let i = 0; i < ids.length; i++) {
            if (ctx.signal?.aborted) {
                return {
                    summary: `Cancelled after ${i}/${ids.length} node(s)`,
                    counts: { created, reused, no_url: noUrl, not_found: notFound, failed, no_image_hash: noImage },
                };
            }
            const seed = await ctx.graph!.get!(ids[i]);
            if (!seed) {
                notFound++;
                continue;
            }
            const pageUrl = urlOf(seed);
            if (!pageUrl) {
                noUrl++;
                continue;
            }

            const target = faviconUrl(pageUrl);
            ctx.progress?.set?.({
                percent: Math.round((100 * i) / ids.length),
                message: ids.length > 1 ? `Fetching favicon from ${target} (${i + 1}/${ids.length})` : `Fetching favicon from ${target}`,
            });
            const res = await ctx.net.probe(target, { method: 'GET', maxBytes: MAX_FAVICON_BYTES, bodyEncoding: 'base64' });
            // A single site's failure (no favicon, transport error) must not sink the rest of the
            // selection — count it and move on rather than aborting the whole run. A redirect is one:
            // it is not followed, and the probe returns it with no body (and no bodyEncoding, which
            // the check below would otherwise take for a probe that cannot send binary).
            if (res.error || res.status === 0 || res.status >= 300) {
                failed++;
                continue;
            }

            // Bytes that were not returned base64-encoded have been UTF-8-decoded, which cannot give
            // the right hash; stop rather than store a wrong one.
            if (res.bodyEncoding !== 'base64') {
                throw new Error('Favicon Hash: the probe did not return the body base64-encoded, so no hash can be computed.');
            }
            if (!res.body || res.truncated) {
                failed++;
                continue;
            }

            const signed = shodanFaviconHash(res.body);
            const bytes = base64ToBytes(res.body);
            const byteCount = bytes.length;
            // Perceptual hashes need the image decoded; an icon favicon-image.ts does not decode gets none.
            const gray = await decodeFavicon(bytes);
            if (!gray) noImage++;

            // createNode merges into the node that already carries this hash (the host dedups by
            // the type's identity), so a re-run refreshes it rather than adding a copy, without
            // node:update. The lookup only tells the summary whether the hash was already known.
            const existing = await findExisting(ctx, 'web.favicon_hash', 'hash_value', String(signed));
            const node: GraphNode = await ctx.graph!.createNode!({
                type: 'web.favicon_hash',
                data: {
                    hash_value: String(signed),
                    hash_algorithm: 'mmh3',
                    // Number's own hex keeps the sign (-30149ea), the form Criminal IP takes.
                    mmh3_hex: signed.toString(16),
                    md5: md5Hex(bytes),
                    sha256: await sha256Hex(bytes),
                    ...(gray ? { phash: phashHex(gray), dhash: dhashHex(gray) } : {}),
                    favicon_url: target,
                    observed_at: new Date().toISOString(),
                },
            });
            if (existing) reused++;
            else created++;
            await ctx.graph!.createEdge!({ from: String(seed.id), to: String(node.id), label: 'has favicon' });
            lastHash = String(signed);
            lastBytes = byteCount;
            lastReused = !!existing;
        }

        const done = created + reused;
        const skipped = noUrl + notFound + failed;
        const skipNote = skipped
            ? ` (${skipped} skipped: ${noUrl} without a URL, ${failed} fetch failure(s), ${notFound} not found)`
            : '';
        const imageNote = noImage ? `; no pHash/dHash for ${noImage} (image not decoded)` : '';
        return {
            summary:
                done === 1
                    ? `Favicon hash ${lastHash} (${lastBytes} bytes)${lastReused ? ' — reused existing node' : ''}${skipNote}${imageNote}`
                    : `${done} favicon(s) hashed (${created} new, ${reused} reused)${skipNote}${imageNote}`,
            counts: {
                created,
                reused,
                no_url: noUrl,
                not_found: notFound,
                failed,
                no_image_hash: noImage,
            },
        };
    },
});
