// DOM Hash plugin — hashes the STRUCTURE of a page's HTML (the ordered sequence of
// tag names), ignoring content, attributes, scripts and styles. Same template → same
// hash, so phishing kits, cloned storefronts and ransomware leak sites cluster even
// after branding, language or embedded resources change.
//
// WHY DESKTOP: the target is dynamic and reading a cross-origin HTML body requires
// CORS, which most hosts do not send. ctx.net.probe (Electron main process) fetches
// the body anonymously, SSRF-guarded.
//
// The technique is dom-hash from The Art of Pivoting: parse tag names in document
// order, join with '|', SHA-256, keep the first 32 hex chars. We implement the tag
// extraction with a lightweight regex over the HTML source — good enough for
// template clustering, no DOM parser dependency.
import { definePlugin } from './sdk';
import type { HostContext, RunResult, GraphNode } from './sdk';

const MAX_HTML_BYTES = 2 * 1024 * 1024; // cap the fetched page

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
 * Extract the ordered tag-name sequence from HTML source.
 *
 * Matches <tag ...> and </tag> and self-closing <tag/>, in document order, capturing
 * the bare name. Comments, doctype, CDATA and processing instructions are skipped.
 * This mirrors the dom-hash algorithm's "ordered list of all HTML tag names" with a
 * fast approximation; it does not build a real DOM, so malformed HTML may produce
 * slightly different sequences than a parser would — acceptable for clustering.
 */
function tagSequence(html: string): string[] {
    const tags: string[] = [];
    const re = /<\/?([a-zA-Z][a-zA-Z0-9]*)(?:\s[^>]*?)?\/?>/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(html)) !== null) {
        const name = m[1].toLowerCase();
        if (name === '!doctype') continue;
        tags.push(name);
    }
    return tags;
}

async function sha256Hex(s: string): Promise<string> {
    const data = new TextEncoder().encode(s);
    const digest = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(digest))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
}

export const domHash = definePlugin({
    manifest: {
        identifier: 'run.vineyard.plugins.dom_hash',
        content_type: 'vineyard:plugin',
        name: 'DOM Structure Hash',
        version: '1.0.0',
        description:
            'Fetches the HTML of the selected URL via the desktop probe and hashes its tag structure (dom-hash) — a template fingerprint that clusters phishing kits and cloned storefronts regardless of text or branding changes. Creates a web.dom_hash node linked to the URL. Desktop only.',
        icon: 'braces',
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
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'web', name: 'dom_hash' },
            ],
        },
        scopes: {
            graph: ['node:read', 'node:create', 'edge:create'],
            web_probe: {
                purpose: 'Fetch the HTML of the selected site to hash its DOM structure (anonymous, SSRF-guarded, desktop only).',
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
                    'DOM hashing needs the desktop shell (cross-origin HTML requires the main-process probe). Run this plugin in the desktop app.',
                counts: { created: 0 },
            };
        }

        ctx.progress?.set?.({ percent: 20, message: `Fetching HTML from ${target}` });
        const res = await ctx.net.probe(target, { method: 'GET', maxBytes: MAX_HTML_BYTES });

        if (res.error || res.status === 0) {
            return { summary: `HTML fetch failed (${res.error || 'no response'})`, counts: { created: 0 } };
        }
        if (res.status >= 400) {
            return { summary: `HTML fetch failed: HTTP ${res.status}`, counts: { created: 0 } };
        }

        const tags = tagSequence(res.body ?? '');
        if (tags.length === 0) {
            return { summary: 'No tags found in the response body', counts: { created: 0 } };
        }
        ctx.progress?.set?.({ percent: 60, message: `Hashing ${tags.length} tags…` });

        const canonical = tags.join('|');
        const full = await sha256Hex(canonical);
        const hash = full.slice(0, 32); // dom-hash truncates to 32 hex chars

        ctx.progress?.set?.({ percent: 80, message: 'Creating dom_hash node…' });
        const node = await ctx.graph!.createNode!({
            type: 'web.dom_hash',
            data: {
                hash_value: hash,
                tag_count: tags.length,
                observed_at: new Date().toISOString(),
            },
        });
        await ctx.graph!.createEdge!({ from: String(seed.id), to: String(node.id), label: 'has dom hash' });

        return {
            summary: `DOM hash ${hash} (${tags.length} tags)`,
            counts: { created: 1 },
        };
    },
});
