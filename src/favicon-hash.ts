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
import { findExisting } from './dedup';

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
        version: '1.1.0',
        description:
            'Fetches the favicon of each selected URL via the desktop probe (no CORS needed), computes its MurmurHash3 hash, and creates a web.favicon_hash node linked to it. Reused favicons are a durable pivot between phishing kits, scam portals and darknet storefronts. Desktop only.',
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
        let lastHash = '';
        let lastBytes = 0;
        let lastReused = false;
        for (let i = 0; i < ids.length; i++) {
            if (ctx.signal?.aborted) {
                return {
                    summary: `Cancelled after ${i}/${ids.length} node(s)`,
                    counts: { created, reused, no_url: noUrl, not_found: notFound, failed },
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
            const res = await ctx.net.probe(target, { method: 'GET', maxBytes: MAX_FAVICON_BYTES });
            // A single site's failure (no favicon, transport error) must not sink the rest of the
            // selection — count it and move on rather than aborting the whole run.
            if (res.error || res.status === 0 || res.status >= 400) {
                failed++;
                continue;
            }

            // The probe returns the body as a string; favicons are binary, so decode the
            // bytes via a UTF-8 round-trip. This preserves the exact byte values for
            // favicons in the BMP range (all real-world .ico/.png), which is what MMH3
            // needs to match Shodan's hash.
            const bytes = new TextEncoder().encode(res.body);
            if (bytes.length === 0) {
                failed++;
                continue;
            }

            const hash = murmur3_32(bytes, 0);
            const signed = shodanForm(hash);

            // De-dup by hand: host createNode's identity check only runs when the type pack
            // is installed in the project, so without this every run adds a fresh node for
            // the same favicon. Reuse the existing node and just re-link the seed to it.
            // A fresh lookup per iteration (not hoisted out of the loop) is what lets two
            // selected sites sharing a favicon dedup against EACH OTHER within this same run.
            const existing = await findExisting(ctx, 'web.favicon_hash', 'hash_value', String(signed));
            let node: GraphNode;
            if (existing) {
                node = existing;
                await ctx.graph!.updateNode!(String(existing.id), {
                    favicon_url: target,
                    observed_at: new Date().toISOString(),
                });
                reused++;
            } else {
                node = await ctx.graph!.createNode!({
                    type: 'web.favicon_hash',
                    data: {
                        hash_value: String(signed),
                        hash_algorithm: 'mmh3',
                        favicon_url: target,
                        observed_at: new Date().toISOString(),
                    },
                });
                created++;
            }
            await ctx.graph!.createEdge!({ from: String(seed.id), to: String(node.id), label: 'has favicon' });
            lastHash = String(signed);
            lastBytes = bytes.length;
            lastReused = !!existing;
        }

        const done = created + reused;
        const skipped = noUrl + notFound + failed;
        const skipNote = skipped
            ? ` (${skipped} skipped: ${noUrl} without a URL, ${failed} fetch failure(s), ${notFound} not found)`
            : '';
        return {
            summary:
                done === 1
                    ? `Favicon hash ${lastHash} (${lastBytes} bytes)${lastReused ? ' — reused existing node' : ''}${skipNote}`
                    : `${done} favicon(s) hashed (${created} new, ${reused} reused)${skipNote}`,
            counts: { created, reused, no_url: noUrl, not_found: notFound, failed },
        };
    },
});
