// De-dup helper for web-recon plugins.
//
// createNode in the host bridge de-duplicates by identity ONLY when the type's
// definition is resolvable from the installed Type Packs — if the pack is not
// installed/activated in the project, resolveType fails, identity comes back null,
// and every run adds another copy of the same fingerprint. This helper does the
// lookup the plugin itself can always do: scan existing nodes of the produced type
// for one carrying the same identifying value, and reuse it.
import type { GraphNode, HostContext } from './sdk';

/**
 * Find an existing node of `type` whose data carries `value` at field `key`.
 * Returns null when none exists (the caller should createNode).
 */
export async function findExisting(
    ctx: HostContext,
    type: string,
    key: string,
    value: string,
): Promise<GraphNode | null> {
    if (!ctx.graph?.list) return null;
    try {
        const { nodes } = await ctx.graph.list({ type });
        return nodes.find((n) => String(n.data?.[key] ?? '') === value) ?? null;
    } catch {
        return null; // read failure → let createNode handle it
    }
}
