// Favicon Hash plugin — fetches a site's favicon and computes its MurmurHash3 (MMH3)
// hash, then creates a web.favicon_hash node linked to the source URL.
//
// WHY DESKTOP: the target is the SELECTED site's favicon, which is dynamic (any host
// the analyst picks) — it cannot be a fixed `network` allowlist entry. And most hosts
// serve favicons without CORS headers, so a browser cannot read the bytes at all. The
// Electron shell's main-process probe (ctx.net.probe) has no same-origin policy and is
// SSRF-guarded, so it fetches the bytes anonymously. Same pattern as whatsmyname.
//
// MMH3 is the de-facto standard for favicon correlation (Shodan uses it): fast, and —
// more importantly — adversaries rarely consider favicons intelligence-relevant, so
// they reuse them verbatim across kits and storefronts. Collisions are acceptable for
// pivoting: the goal is repeatability, not uniqueness.
import { definePlugin } from './sdk';
import type { HostContext, RunResult, GraphNode } from './sdk';

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

export const faviconHash = definePlugin({
    manifest: {
        identifier: 'run.vineyard.plugins.favicon_hash',
        content_type: 'vineyard:plugin',
        name: 'Favicon Hash',
        version: '1.0.0',
        description:
            'Fetches the favicon of the selected URL via the desktop probe (no CORS needed), computes its MurmurHash3 hash, and creates a web.favicon_hash node linked to it. Reused favicons are a durable pivot between phishing kits, scam portals and darknet storefronts. Desktop only.',
        icon: 'image',
        author: { name: 'VINEYARD', url: 'https://vineyard.run' },
        license: 'Apache-2.0',
        platforms: {
            primary: 'desktop',
            web: { runtime: 'sandbox-js', entry: 'inline' },
            desktop: { runtime: 'sandbox-js', entry: 'inline', min_app_version: '0.1.0' },
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
                purpose: 'Fetch the favicon of the selected site (anonymous, SSRF-guarded, desktop only).',
            },
        },
        lifecycle: { persistence: 'opt-in', controls: ['progress', 'cancel'], progress: 'determinate' },
    },

    async run(ctx: HostContext): Promise<RunResult> {
        const selId = ctx.input.selection[0];
        if (!selId) return { summary: 'Select a URL node first', counts: { created: 0 } };
        const seed = await ctx.graph!.get!(selId);
        if (!seed) return { summary: 'Selected node not found', counts: { created: 0 } };
        const pageUrl = urlOf(seed);
        if (!pageUrl) return { summary: 'Selected node has no valid URL', counts: { created: 0 } };

        if (!ctx.net?.probe) {
            return {
                summary:
                    'Favicon hashing needs the desktop shell (the target is dynamic and favicons are usually served without CORS headers). Run this plugin in the desktop app.',
                counts: { created: 0 },
            };
        }

        const target = faviconUrl(pageUrl);
        ctx.progress?.set?.({ percent: 20, message: `Fetching favicon from ${target}` });
        const res = await ctx.net.probe(target, { method: 'GET', maxBytes: MAX_FAVICON_BYTES });

        if (res.error || res.status === 0) {
            return { summary: `Favicon fetch failed (${res.error || 'no response'})`, counts: { created: 0 } };
        }
        if (res.status === 404 || res.status === 403) {
            return { summary: `No favicon at ${target} (HTTP ${res.status})`, counts: { created: 0 } };
        }
        if (res.status >= 400) {
            return { summary: `Favicon fetch failed: HTTP ${res.status}`, counts: { created: 0 } };
        }

        // The probe returns the body as a string; favicons are binary, so decode the
        // bytes via a UTF-8 round-trip. This preserves the exact byte values for
        // favicons in the BMP range (all real-world .ico/.png), which is what MMH3
        // needs to match Shodan's hash.
        const bytes = new TextEncoder().encode(res.body);
        if (bytes.length === 0) {
            return { summary: 'Favicon is empty (0 bytes)', counts: { created: 0 } };
        }
        ctx.progress?.set?.({ percent: 60, message: `Hashing ${bytes.length} bytes…` });

        const hash = murmur3_32(bytes, 0);
        const signed = shodanForm(hash);
        ctx.progress?.set?.({ percent: 80, message: 'Creating favicon_hash node…' });

        const node = await ctx.graph!.createNode!({
            type: 'web.favicon_hash',
            data: {
                hash_value: String(signed),
                hash_algorithm: 'mmh3',
                favicon_url: target,
                observed_at: new Date().toISOString(),
            },
        });
        await ctx.graph!.createEdge!({ from: String(seed.id), to: String(node.id), label: 'has favicon' });

        return {
            summary: `Favicon hash ${signed} (${bytes.length} bytes)`,
            counts: { created: 1 },
        };
    },
});
