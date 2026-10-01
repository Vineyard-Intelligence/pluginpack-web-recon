// Web Recon pack — web-page fingerprints: favicon hash (Shodan's MMH3), HHHash (response header
// names) and a DOM tag-structure hash. Desktop only: the targets are arbitrary sites, fetched with
// ctx.net.probe.
import { definePluginPack } from './sdk';
import { faviconHash } from './favicon-hash';
import { hhhash } from './hhhash';
import { domHash } from './dom-hash';

export default definePluginPack({
    identifier: 'run.vineyard.pluginpacks.web_recon',
    content_type: 'vineyard:pluginpack',
    name: 'Web Recon',
    version: '1.2.1',
    description:
        'Fingerprints web pages: Shodan-style favicon hash, HHHash of the response header names, and a hash of the HTML tag structure. Desktop only.',
    plugins: [faviconHash, hhhash, domHash],
});
