// Web Recon pack — web-page fingerprints: favicon hashes (Shodan's MMH3, MD5, SHA-256, pHash, dHash),
// HHHash (response header names) and a DOM tag-structure hash. Desktop only: the targets are arbitrary
// sites, fetched with ctx.net.probe.
import { definePluginPack } from './sdk';
import { faviconHash } from './favicon-hash';
import { hhhash } from './hhhash';
import { domHash } from './dom-hash';

// The pack's page, shown under the summary line when the pack is opened in the marketplace. It is
// Markdown rendered without images or raw HTML, and links show as text, so URLs are written out.
// The plugins, their node types and the permissions are listed right below it, so the page says
// only what that list does not: what the pack is for, who sees what, and how to read the results.
const PACK_PAGE = [
    "Fingerprints to pivot on when operators rotate domains, IP addresses and certificates but reuse what sits underneath: a phishing kit's favicon, a server stack's header layout, a storefront template's markup. A fingerprint shared by otherwise unrelated hosts is a lead for clustering them (Tor and clear web, staging and production, a clone and its original).",
    '',
    "**Who sees it:** the target. Every plugin requests the selected site directly from the analyst's machine, one request per URL, with no cookies or credentials. No third-party service is queried; the hashes are looked up on the search services separately.",
    '',
    '**Read results with care:**',
    "- A common default icon (a framework's, a hosting panel's) matches unrelated sites. An HHHash reflects the server stack, so a shared one points at the same deployment practice.",
    '- `phash` and `dhash` are compared by bit distance, not equality; Krawetz counts 10 or fewer differing bits as a likely variant. Censys and VirusTotal do not document their perceptual hashes, so equivalence with their values is not established.',
    '- HHHash fingerprints any status, 403 and 404 included: an error page still shows the stack. The DOM hash ignores text and attributes, so a template keeps its hash when its text, branding or language change.',
    '',
    "**Data and licences:** none shipped; every value is computed from the site's own response. HHHash is computed as the reference `hhhash` package does (https://github.com/adulau/HHHash), so values compare with other tools'. The DOM hash is the dom-hash technique from The Art of Pivoting.",
    '',
    '**Source:** https://github.com/Vineyard-Intelligence/pluginpack-web-recon (Apache-2.0)',
].join('\n');

export default definePluginPack({
    identifier: 'run.vineyard.pluginpacks.web_recon',
    content_type: 'vineyard:pluginpack',
    name: 'Web Recon',
    version: '1.4.1',
    summary:
        'Fingerprints web pages: favicon hashes in the forms Shodan, Censys and other search services index, HHHash of the response header names, and a hash of the HTML tag structure. Desktop only.',
    description: PACK_PAGE,
    plugins: [faviconHash, hhhash, domHash],
});
