// Web Recon pack — web-page fingerprints: favicon hashes (Shodan's MMH3, MD5, SHA-256, pHash, dHash),
// HHHash (response header names) and a DOM tag-structure hash. Desktop only: the targets are arbitrary
// sites, fetched with ctx.net.probe.
import { definePluginPack } from './sdk';
import { faviconHash } from './favicon-hash';
import { hhhash } from './hhhash';
import { domHash } from './dom-hash';

export default definePluginPack({
    identifier: 'run.vineyard.pluginpacks.web_recon',
    content_type: 'vineyard:pluginpack',
    name: 'Web Recon',
    version: '1.3.0',
    description:
        'Fingerprints web pages: favicon hashes in the forms Shodan, Censys and other search services index, HHHash of the response header names, and a hash of the HTML tag structure. Desktop only.',
    plugins: [faviconHash, hhhash, domHash],
});
