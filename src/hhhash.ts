// HHHash plugin — HTTP Header Hashing (https://github.com/adulau/HHHash): "hhh:1:" + SHA-256 of
// the response header NAMES in the order the server sent them, joined with ':'.
//
// Computed the way the reference implementation (the `hhhash` Python package, buildhash) does, so the
// values compare with other tools': an HTTP/1.1 GET (HTTP/2 lowercases names), without following
// redirects, sending the request headers that client sends, with repeated names (Set-Cookie…)
// counted once at their first position — and in their original case. Checked against the package
// on live sites, including the values its README publishes.
import { definePlugin } from './sdk';
import type { HostContext, RunResult, GraphNode } from './sdk';
import { findExisting } from './dedup';

const MAX_HEADER_BYTES = 64 * 1024; // headers are small; this is generous

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

/** HHHash of header names as received: first occurrence of each (case-insensitive), joined with ':'. */
export async function hhhashOf(names: string[]): Promise<{ value: string; count: number }> {
    const seen = new Set<string>();
    const kept = names.filter((n) => {
        const k = n.toLowerCase();
        if (seen.has(k)) return false;
        seen.add(k);
        return true;
    });
    return { value: `hhh:1:${await sha256Hex(kept.join(':'))}`, count: kept.length };
}

async function sha256Hex(s: string): Promise<string> {
    const data = new TextEncoder().encode(s);
    const digest = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(digest))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
}

export const hhhash = definePlugin({
    manifest: {
        identifier: 'run.vineyard.plugins.hhhash',
        content_type: 'vineyard:plugin',
        name: 'HTTP Header Hash (HHHash)',
        version: '1.2.1',
        description:
            'Requests each selected URL over HTTP/1.1 and creates a web.hhhash node with its HHHash (hhh:1: plus the SHA-256 of the response header names in order), linked by "has header hash"; also records the header count and Server value. Does not follow redirects. Desktop only.',
        icon: 'file-code',
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
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'web', name: 'hhhash' },
            ],
        },
        scopes: {
            graph: ['node:read', 'node:create', 'edge:create'],
            web_probe: {
                purpose: 'Fetch the response headers of each selected site.',
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
                    'HHHash needs the desktop shell (cross-origin response headers require the main-process probe). Run this plugin in the desktop app.',
                counts: { created: 0 },
            };
        }

        let created = 0;
        let reused = 0;
        let noUrl = 0;
        let notFound = 0;
        let failed = 0;
        let lastHash = '';
        let lastHeaderCount = 0;
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
            const target = urlOf(seed);
            if (!target) {
                noUrl++;
                continue;
            }

            ctx.progress?.set?.({
                percent: Math.round((100 * i) / ids.length),
                message: ids.length > 1 ? `Fetching headers from ${target} (${i + 1}/${ids.length})` : `Fetching headers from ${target}`,
            });
            const res = await ctx.net.probe(target, {
                method: 'GET',
                headers: { Accept: '*/*', 'Accept-Encoding': 'gzip, deflate' },
                headerNames: true,
            });
            // Any status is fingerprinted, as the reference does: a 403 or 404 still shows the stack.
            if (res.error || res.status === 0) {
                failed++;
                continue;
            }

            // Without the header names as sent (a probe that answered over HTTP/2 lowercases them)
            // there is no HHHash, so stop rather than store a wrong one.
            if (!Array.isArray(res.headerNames)) {
                throw new Error('HHHash: the probe returned no header names, so no hash can be computed.');
            }
            if (!res.headerNames.length) {
                failed++;
                continue;
            }

            const { value: hash, count: headerCount } = await hhhashOf(res.headerNames);
            const serverHint = (res.headers ?? {})['server'] ?? '';

            // createNode merges into the node that already carries this hash (the host dedups by
            // the type's identity), so a re-run refreshes it rather than adding a copy, without
            // node:update. The lookup only tells the summary whether the hash was already known.
            const existing = await findExisting(ctx, 'web.hhhash', 'hash_value', hash);
            const node: GraphNode = await ctx.graph!.createNode!({
                type: 'web.hhhash',
                data: {
                    hash_value: hash,
                    header_count: headerCount,
                    server_hint: serverHint || undefined,
                    observed_at: new Date().toISOString(),
                },
            });
            if (existing) reused++;
            else created++;
            await ctx.graph!.createEdge!({ from: String(seed.id), to: String(node.id), label: 'has header hash' });
            lastHash = hash;
            lastHeaderCount = headerCount;
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
                    ? `HHHash ${lastHash.slice(0, 12)}… (${lastHeaderCount} headers)${lastReused ? ' — reused existing node' : ''}${skipNote}`
                    : `${done} host(s) fingerprinted (${created} new, ${reused} reused)${skipNote}`,
            counts: { created, reused, no_url: noUrl, not_found: notFound, failed },
        };
    },
});
