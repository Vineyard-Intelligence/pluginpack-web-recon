// Web Recon pack — collects fingerprints from web pages: favicon hash (MMH3),
// HTTP header hash (HHHash), and DOM structure hash (dom-hash).
//
// All three are DESKTOP-only: the targets are dynamic (the selected site) and
// reading cross-origin bodies/headers requires CORS, which most hosts do not send.
// ctx.net.probe (Electron main process) fetches them anonymously, SSRF-guarded —
// same pattern as WhatsMyName.
//
// Each fingerprint is a pivot primitive: shared favicon / header structure / DOM
// template across otherwise unrelated hosts indicates shared deployment practice.
import { definePluginPack } from './sdk';
import { faviconHash } from './favicon-hash';
import { hhhash } from './hhhash';
import { domHash } from './dom-hash';

export default definePluginPack({
    identifier: 'run.vineyard.pluginpacks.web_recon',
    content_type: 'vineyard:pluginpack',
    name: 'Web Recon',
    version: '1.1.0',
    description:
        'Web page fingerprinting for Vineyard: favicon hash (MMH3), HTTP header hash (HHHash), and DOM structure hash (dom-hash) — reusable pivot primitives for clustering related infrastructure. Runs the whole selection in one pass. Desktop only.',
    plugins: [faviconHash, hhhash, domHash],
});
