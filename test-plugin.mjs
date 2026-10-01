// Checks the two hashes other tools must agree with, through the plugins' real run().
// Run: node test-plugin.mjs   (after `npm run build`)
//
// Expected values come from the reference implementations, not from this code:
//   favicon  Python `mmh3.hash(codecs.encode(data, 'base64'))` — Shodan's http.favicon.hash
//   HHHash   the `hhhash` package (buildhash); adca8a87… is the value its README publishes for
//            www.misp-project.org, whose header names are listed below.
import pack from './dist/pack.mjs';

const [favicon, hhhash] = pack.plugins;
let fail = 0;
const check = (name, cond) => {
    console.log(`${cond ? '  ok  ' : '  FAIL'} ${name}`);
    if (!cond) fail++;
};

function ctxWith(probeResponse) {
    const created = [];
    const calls = [];
    return {
        created,
        calls,
        ctx: {
            input: { selection: ['u1'] },
            graph: {
                get: async () => ({ id: 'u1', type: 'web.url', data: { url: 'https://example.com/page' } }),
                list: async () => ({ nodes: [] }),
                createNode: async (d) => {
                    const n = { id: `n${created.length + 1}`, ...d };
                    created.push(n);
                    return n;
                },
                updateNode: async () => {},
                createEdge: async () => {},
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
    check('an app without bodyEncoding is refused, not hashed wrongly', err instanceof Error && /0\.4\.15/.test(err.message));
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
    check('an app without headerNames is refused', err instanceof Error && /0\.4\.15/.test(err.message));
}

console.log(fail ? `\n${fail} FAILED` : '\nall checks passed');
if (fail) process.exit(1);
