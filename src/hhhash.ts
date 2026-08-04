// HHHash plugin — HTTP Header Hashing: fingerprints a server by the STRUCTURE of its
// HTTP/1 response headers (which headers, in which order), ignoring volatile values.
//
// WHY DESKTOP: the target is dynamic (the selected site), and reading response headers
// cross-origin requires CORS — which most hosts do not send. ctx.net.probe runs in the
// Electron main process and returns the response headers, no CORS needed.
//
// The hash covers header NAMES in ORDER (lowercased, first-occurrence de-duplicated),
// following the HHHash technique (https://www.foo.be/2023/07/HTTP-Headers-Hashing_HHHash):
// the same server stack / reverse-proxy / framework config produces the same hash, so
// clusters of hosts sharing an HHHash share deployment practice — even when domains,
// IPs and certificates all differ.
import { definePlugin } from './sdk';
import type { HostContext, RunResult, GraphNode } from './sdk';

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

/**
 * Build the HHHash canonical string: header names in response order, lowercased,
 * first occurrence only (probe headers are already lowercased, minus set-cookie).
 * Values are intentionally excluded — they are volatile (dates, tokens).
 */
function canonicalHeaderNames(headers: Record<string, string>): string {
    const names: string[] = [];
    const seen = new Set<string>();
    for (const name of Object.keys(headers)) {
        const n = name.toLowerCase().trim();
        if (!n || seen.has(n)) continue;
        // set-cookie is stripped by the probe; skip hop-by-hop noise defensively.
        if (n === 'set-cookie' || n === 'connection' || n === 'keep-alive') continue;
        seen.add(n);
        names.push(n);
    }
    return names.join('|');
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
        version: '1.0.0',
        description:
            'Fetches the response headers of the selected URL via the desktop probe and computes their HHHash (hash of header-name structure) — a stable fingerprint of the server stack behind the host. Creates a web.hhhash node linked to the URL. Desktop only.',
        icon: 'file-code',
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
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'web', name: 'hhhash' },
            ],
        },
        scopes: {
            graph: ['node:read', 'node:create', 'edge:create'],
            web_probe: {
                purpose: 'Fetch the response headers of the selected site (anonymous, SSRF-guarded, desktop only).',
            },
        },
        lifecycle: { persistence: 'opt-in', controls: ['progress', 'cancel'], progress: 'determinate' },
    },

    async run(ctx: HostContext): Promise<RunResult> {
        const selId = ctx.input.selection[0];
        if (!selId) return { summary: 'Select a URL node first', counts: { created: 0 } };
        const seed = await ctx.graph!.get!(selId);
        if (!seed) return { summary: 'Selected node not found', counts: { created: 0 } };
        const target = urlOf(seed);
        if (!target) return { summary: 'Selected node has no valid URL', counts: { created: 0 } };

        if (!ctx.net?.probe) {
            return {
                summary:
                    'HHHash needs the desktop shell (cross-origin response headers require the main-process probe). Run this plugin in the desktop app.',
                counts: { created: 0 },
            };
        }

        ctx.progress?.set?.({ percent: 20, message: `Fetching headers from ${target}` });
        const res = await ctx.net.probe(target, { method: 'HEAD', maxBytes: 0 });

        if (res.error || res.status === 0) {
            return { summary: `Header fetch failed (${res.error || 'no response'})`, counts: { created: 0 } };
        }
        if (res.status >= 400) {
            return { summary: `Header fetch failed: HTTP ${res.status}`, counts: { created: 0 } };
        }

        const names = Object.keys(res.headers ?? {});
        if (names.length === 0) {
            return { summary: 'No headers returned by the probe', counts: { created: 0 } };
        }
        ctx.progress?.set?.({ percent: 60, message: `Hashing ${names.length} header names…` });

        const canonical = canonicalHeaderNames(res.headers ?? {});
        const hash = await sha256Hex(canonical);
        const serverHint = (res.headers ?? {})['server'] ?? '';

        ctx.progress?.set?.({ percent: 80, message: 'Creating hhhash node…' });
        const node = await ctx.graph!.createNode!({
            type: 'web.hhhash',
            data: {
                hash_value: hash,
                header_count: canonical.split('|').filter(Boolean).length,
                server_hint: serverHint || undefined,
                observed_at: new Date().toISOString(),
            },
        });
        await ctx.graph!.createEdge!({ from: String(seed.id), to: String(node.id), label: 'has header hash' });

        return {
            summary: `HHHash ${hash.slice(0, 12)}… (${canonical.split('|').filter(Boolean).length} headers)`,
            counts: { created: 1 },
        };
    },
});
