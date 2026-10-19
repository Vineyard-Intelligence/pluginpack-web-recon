// Checks the two hashes other tools must agree with, through the plugins' real run().
// Run: node test-plugin.mjs   (after `npm run build`)
//
// Expected values come from the reference implementations, not from this code:
//   favicon  Python `mmh3.hash(codecs.encode(data, 'base64'))` — Shodan's http.favicon.hash;
//            MD5 and SHA-256 of the raw bytes from Node's crypto; pHash and dHash from Pillow and
//            ImageHash, written into test-fixtures/favicons/expected.json by make-favicons.py
//   HHHash   the `hhhash` package (buildhash); adca8a87… is the value its README publishes for
//            www.misp-project.org, whose header names are listed below.
import { createHash } from 'node:crypto';
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
    const raw = Buffer.from(body, 'base64');
    check('md5 is of the raw bytes', t.created[0]?.data.md5 === createHash('md5').update(raw).digest('hex'));
    check('sha256 is of the raw bytes', t.created[0]?.data.sha256 === createHash('sha256').update(raw).digest('hex'));
    // Python format(-1874651529, 'x'): the form Criminal IP's favicon: filter takes.
    check('mmh3_hex is the signed value in hex', t.created[0]?.data.mmh3_hex === '-6fbce989');
}
// pHash and dHash on reference icons, each as Pillow and ImageHash compute it (make-favicons.py).
{
    const dir = new URL('./test-fixtures/favicons/', import.meta.url);
    const expected = JSON.parse(readFileSync(new URL('expected.json', dir), 'utf8'));
    for (const [name, want] of Object.entries(expected)) {
        const body = readFileSync(new URL(name, dir)).toString('base64');
        const t = ctxWith({
            status: 200,
            headers: {},
            body,
            truncated: false,
            bodyEncoding: 'base64',
        });
        const res = await favicon.run(t.ctx);
        const got = t.created[0]?.data ?? {};
        if (want.phash) {
            check(`${name}: phash as ImageHash computes it`, got.phash === want.phash);
            check(`${name}: dhash as VirusTotal packs it`, got.dhash === want.dhash);
        } else {
            check(`${name}: not decoded, so no perceptual hash`, !('phash' in got) && res.counts.no_image_hash === 1);
        }
    }
}

// A redirect is not followed, and the probe returns it without a body or bodyEncoding: it is a
// skipped fetch, not a reason to stop hashing the rest of the selection.
{
    const body = Buffer.from([0, 1, 2, 3]).toString('base64');
    const t = ctxWith({
        status: 200,
        headers: {},
        body,
        truncated: false,
        bodyEncoding: 'base64',
    });
    t.ctx.input.selection = ['u1', 'u2'];
    let n = 0;
    t.ctx.net.probe = async () =>
        n++ === 0
            ? {
                  status: 301,
                  headers: {},
                  body: '',
                  truncated: false,
                  redirectUrl: 'https://www.example.com/favicon.ico',
              }
            : {
                  status: 200,
                  headers: {},
                  body,
                  truncated: false,
                  bodyEncoding: 'base64',
              };
    const res = await favicon.run(t.ctx).catch((e) => e);
    check('a redirect is skipped and the next site is still hashed', !(res instanceof Error) && t.created.length === 1);
    check('and counted as a failed fetch', res?.counts?.failed === 1);
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
