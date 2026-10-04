// Lookup helper for web-recon plugins.
//
// The host's createNode already merges a fingerprint into the existing node with the same
// identity, so this is not what dedups. It only answers "was this hash already in the graph?"
// for the run summary ("reused existing node" vs "new"). It sees committed nodes, not ones this
// run has staged.
import type { GraphNode, HostContext } from './sdk';

/**
 * Find an existing node of `type` whose data carries `value` at field `key`.
 * Returns null when none exists.
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
