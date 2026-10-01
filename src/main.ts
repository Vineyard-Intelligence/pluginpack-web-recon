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
    version: '1.1.1',
    description:
        'Fingerprints web pages by hashing their favicon (MMH3), response header names and HTML tag structure. Desktop only.',
    plugins: [faviconHash, hhhash, domHash],
});
