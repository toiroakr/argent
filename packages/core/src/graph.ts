/** Shared reachability helpers for deps.dev resolved dependency graphs. */

export interface GraphEdge {
  fromNode: number;
  toNode: number;
}

/** Builds an adjacency list (node index -> reachable node indices) from graph edges. */
export function buildAdjacency(edges: GraphEdge[]): Map<number, number[]> {
  const adj = new Map<number, number[]>();
  for (const e of edges) {
    const list = adj.get(e.fromNode) ?? [];
    list.push(e.toNode);
    adj.set(e.fromNode, list);
  }
  return adj;
}

/**
 * Nodes reachable from `from`, never traversing into `blocked` (-1 = nothing
 * blocked). The returned set includes `from`. Used to find which nodes a
 * dependency *exclusively* pulls: nodes reachable normally but not when its
 * node is blocked are the ones only it brings in (its dominator set).
 */
export function reachableAvoiding(
  adj: Map<number, number[]>,
  from: number,
  blocked: number,
): Set<number> {
  const seen = new Set<number>([from]);
  const stack = [from];
  while (stack.length) {
    const n = stack.pop()!;
    for (const m of adj.get(n) ?? []) {
      if (m === blocked || seen.has(m)) continue;
      seen.add(m);
      stack.push(m);
    }
  }
  return seen;
}
