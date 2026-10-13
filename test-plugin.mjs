// Checks the two hashes other tools must agree with, through the plugins' real run().
// Run: node test-plugin.mjs   (after `npm run build`)
//
// Expected values come from the reference implementations, not from this code:
//   favicon  Python `mmh3.hash(codecs.encode(data, 'base64'))` — Shodan's http.favicon.hash
//   HHHash   the `hhhash` package (buildhash); adca8a87… is the value its README publishes for
//            www.misp-project.org, whose header names are listed below.
import { readFileSync } from 'node:fs';
import pack from './dist/pack.mjs';

const [favicon, hhhash] = pack.plugins;
let fail = 0;
const check = (name, cond) => {
    console.log(`${cond ? '  ok  ' : '  FAIL'} ${name}`);
    if (!cond) fail++;
};

// No updateNode: the plugins declare no node:update, and the host only provides it under that scope.
function ctxWith(probeResponse, existing = []) {
    const created = [];
    const calls = [];
    const edges = [];
    return {
        created,
        calls,
        edges,
        ctx: {
            input: { selection: ['u1'] },
            graph: {
                get: async () => ({ id: 'u1', type: 'web.url', data: { url: 'https://example.com/page' } }),
                list: async ({ type } = {}) => ({ nodes: existing.filter((n) => !type || n.type === type) }),
                createNode: async (d) => {
                    const n = { id: `n${created.length + 1}`, ...d };
                    created.push(n);
                    return n;
                },
                createEdge: async (e) => {
                    edges.push(e);
                },
            },
            net: {
                probe: async (url, init) => {
                    calls.push({ url, init });
                    return probeResponse;
                },
            },
            progress: { set() {}, log() {} },
        },
    };
}

// ── favicon: Shodan's MMH3 of the base64 text, wrapped at 76 columns ─────────────────────────
{
    const body = Buffer.from(Array.from({ length: 200 }, (_, i) => i)).toString('base64');
    const t = ctxWith({ status: 200, headers: {}, body, truncated: false, bodyEncoding: 'base64' });
    await favicon.run(t.ctx);
    check('asks the probe for base64', t.calls[0]?.init?.bodyEncoding === 'base64');
    check('fetches /favicon.ico', t.calls[0]?.url === 'https://example.com/favicon.ico');
    check('hash equals Python mmh3 over encodebytes', t.created[0]?.data.hash_value === '-1874651529');
}
{
    const t = ctxWith({ status: 200, headers: {}, body: 'GIF89a', truncated: false });
    const err = await favicon.run(t.ctx).catch((e) => e);
    check('a body without bodyEncoding is refused, not hashed wrongly', err instanceof Error && /base64/.test(err.message));
}

// ── HHHash: hhh:1: + SHA-256 of names as sent, repeats counted once ─────────────────────────
{
    const names = 'Date:Server:Last-Modified:ETag:Accept-Ranges:Vary:Content-Encoding:Content-Length:Keep-Alive:Connection:Content-Type'.split(':');
    const t = ctxWith({ status: 200, headers: { server: 'Apache' }, body: '', truncated: false, headerNames: names });
    await hhhash.run(t.ctx);
    check('asks for header names over a GET', t.calls[0]?.init?.headerNames === true && t.calls[0]?.init?.method === 'GET');
    check(
        'matches the published reference value',
        t.created[0]?.data.hash_value === 'hhh:1:adca8a87f2a537dbbf07ba6d8cba6db53fde257ae2da4dad6f3ee6b47080c53f',
    );
    check('records the header count and Server', t.created[0]?.data.header_count === 11 && t.created[0]?.data.server_hint === 'Apache');
}
{
    const t = ctxWith({ status: 404, headers: {}, body: '', truncated: false, headerNames: ['Date', 'Set-Cookie', 'set-cookie', 'Server'] });
    await hhhash.run(t.ctx);
    check(
        'a repeated name counts once, first spelling kept; a 404 is still hashed',
        t.created[0]?.data.hash_value === 'hhh:1:e0350144c0d96986bac1a9ac74b68bc67f88fd07fcd9e7ea93d77030d653fbb5',
    );
}
{
    const t = ctxWith({ status: 200, headers: { date: 'x' }, body: '', truncated: false });
    const err = await hhhash.run(t.ctx).catch((e) => e);
    check('a probe without headerNames is refused', err instanceof Error && /header names/.test(err.message));
}

// ── a re-run on a hash already in the graph: createNode again (the host merges it into the
//    existing node), never updateNode, which throws without node:update.
{
    const names = ['Date', 'Server'];
    const hash = 'hhh:1:' + 'x'.repeat(64);
    const t = ctxWith({ status: 200, headers: {}, body: '', truncated: false, headerNames: names }, []);
    await hhhash.run(t.ctx);
    const known = { id: 'h1', type: 'web.hhhash', data: { hash_value: t.created[0]?.data.hash_value ?? hash } };
    const again = ctxWith({ status: 200, headers: {}, body: '', truncated: false, headerNames: names }, [known]);
    const res = await hhhash.run(again.ctx).catch((e) => e);
    check('a re-run on a known hash succeeds without updateNode', !(res instanceof Error));
    check(
        'and re-creates it by identity so the host merges it',
        again.created[0]?.data.hash_value === known.data.hash_value && again.edges.length === 1,
    );
    check('the summary says the hash was already known', /reused|existing/i.test(res?.summary ?? ''));
}

// ── scopes: the app grants from the JSON manifest, so it must say what the bundle says.
{
    const json = JSON.parse(readFileSync(new URL('./plugins/web-recon.manifest.json', import.meta.url), 'utf8'));
    for (const p of pack.plugins) {
        const m = json.plugins.find((x) => x.identifier === p.manifest.identifier);
        check(
            `${p.manifest.identifier}: same graph scopes as the JSON manifest`,
            JSON.stringify(m?.scopes.graph) === JSON.stringify(p.manifest.scopes.graph),
        );
    }
}

console.log(fail ? `\n${fail} FAILED` : '\nall checks passed');
if (fail) process.exit(1);
