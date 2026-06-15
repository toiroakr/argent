import { getJson } from "./http.js";
import { makeRegistry, type RegistryClient } from "./npm.js";
import { findSensitiveTerms, recommendBuildVsBuy } from "./providers/reimplementability.js";
import { scoreDrop, type AuditEntry } from "./audit.js";

const REGISTRY = "https://registry.npmjs.org";
const DEPSDEV = "https://api.deps.dev/v3";

/** One of the packages you manage, with its declared dependencies. */
export interface CommonsManifest {
  name: string;
  entries: AuditEntry[];
}

export interface CommonDep {
  name: string;
  version: string;
  /** Names of your packages that depend on this. */
  usedBy: string[];
  usageCount: number;
  /** True only when every consumer lists it under devDependencies. */
  dev: boolean;
  unpackedSize?: number;
  transitiveDeps: number;
  footprintBytes?: number;
  footprintApprox?: boolean;
  sensitive: boolean;
  verdict: ReturnType<typeof recommendBuildVsBuy>["verdict"];
  /** 0-100 how inline-able the dep itself is (standalone). */
  reimplementScore: number;
  /** 0-100 reimplementation value = inline-ability × how widely you use it. */
  commonsScore: number;
  reasons: string[];
}

export interface CommonsReport {
  /** The packages analyzed. */
  packages: string[];
  /** Common dependencies ranked by commonsScore (descending). */
  deps: CommonDep[];
  generatedAt: string;
}

export interface CommonsOptions {
  fetch?: typeof fetch;
  /** Minimum number of your packages that must use a dep to list it (default 2). */
  minUsage?: number;
  concurrency?: number;
}

interface GraphNode {
  versionKey: { name: string; version: string };
}

async function resolveVersion(
  name: string,
  fetchImpl: typeof fetch,
): Promise<string | undefined> {
  try {
    const pkg = await getJson<{
      versions?: { versionKey: { version: string }; isDefault?: boolean }[];
    }>(`${DEPSDEV}/systems/npm/packages/${encodeURIComponent(name)}`, { fetch: fetchImpl });
    const versions = pkg.versions ?? [];
    return (versions.find((v) => v.isDefault) ?? versions.at(-1))?.versionKey.version;
  } catch {
    return undefined;
  }
}

async function subtree(
  name: string,
  version: string,
  fetchImpl: typeof fetch,
  registry: RegistryClient,
): Promise<{ deps: number; bytes: number; complete: boolean }> {
  let nodes: GraphNode[] = [];
  try {
    const g = await getJson<{ nodes?: GraphNode[] }>(
      `${DEPSDEV}/systems/npm/packages/${encodeURIComponent(name)}/versions/${encodeURIComponent(version)}:dependencies`,
      { fetch: fetchImpl },
    );
    nodes = g.nodes ?? [];
  } catch {
    nodes = [];
  }
  const keys = nodes.length ? nodes.map((n) => n.versionKey) : [{ name, version }];
  const sizes = await Promise.all(keys.map((k) => registry.size(k.name, k.version)));
  let bytes = 0;
  let complete = true;
  for (const s of sizes) {
    if (typeof s === "number") bytes += s;
    else complete = false;
  }
  return { deps: Math.max(0, keys.length - 1), bytes, complete };
}

async function mapLimit<T, R>(
  items: T[],
  limit: number,
  fn: (item: T) => Promise<R>,
): Promise<R[]> {
  const out = new Array<R>(items.length);
  let cursor = 0;
  await Promise.all(
    Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, async () => {
      while (true) {
        const i = cursor++;
        if (i >= items.length) break;
        out[i] = await fn(items[i]!);
      }
    }),
  );
  return out;
}

/**
 * Finds dependencies shared across several packages you manage and ranks them
 * by reimplementation value: a small, mundane dependency used by many of your
 * packages is a prime candidate to implement once internally and drop from all
 * of them — the effort amortizes across every consumer.
 */
export async function auditCommons(
  manifests: CommonsManifest[],
  options: CommonsOptions = {},
): Promise<CommonsReport> {
  const fetchImpl = options.fetch ?? globalThis.fetch;
  if (!fetchImpl) throw new Error("No fetch implementation available");
  const registry = makeRegistry(fetchImpl);
  const minUsage = options.minUsage ?? 2;

  // Aggregate usage across packages.
  const usage = new Map<string, { usedBy: Set<string>; devOnly: boolean }>();
  for (const m of manifests) {
    for (const e of m.entries) {
      const u = usage.get(e.name) ?? { usedBy: new Set<string>(), devOnly: true };
      u.usedBy.add(m.name);
      if (!e.dev) u.devOnly = false;
      usage.set(e.name, u);
    }
  }

  const common = [...usage.entries()].filter(([, u]) => u.usedBy.size >= minUsage);
  const maxUsage = common.reduce((m, [, u]) => Math.max(m, u.usedBy.size), 1);

  const deps = await mapLimit(
    common,
    options.concurrency ?? 8,
    async ([name, u]): Promise<CommonDep | null> => {
    const version = await resolveVersion(name, fetchImpl);
    if (!version) return null;
    const [reg, tree] = await Promise.all([
      registry.doc(name),
      subtree(name, version, fetchImpl, registry),
    ]);
    const ver = reg?.versions?.[version];
    const unpackedSize = ver?.dist?.unpackedSize;
    const keywords = reg?.keywords ?? ver?.keywords ?? [];
    const sensitiveHits = findSensitiveTerms(name, keywords, reg?.description ?? "");
    const verdict = recommendBuildVsBuy({
      unpackedSize,
      fileCount: ver?.dist?.fileCount,
      directDeps: ver?.dependencies ? Object.keys(ver.dependencies).length : undefined,
      transitiveDeps: tree.deps,
      sensitiveHits,
    });
    const reimplementScore = scoreDrop({
      sensitive: sensitiveHits.length > 0,
      ownBytes: unpackedSize,
      footprintBytes: tree.bytes,
      transitiveDeps: tree.deps,
    });
    // Wider use → more value in reimplementing once. 1 user would be 0.2, the
    // most-used dep 1.0.
    const usageWeight = 0.2 + 0.8 * ((u.usedBy.size - 1) / Math.max(1, maxUsage - 1));
    const commonsScore = Math.round(reimplementScore * usageWeight);

    const reasons: string[] = [`used by ${u.usedBy.size} of your packages`];
    if (sensitiveHits.length) reasons.push("security-sensitive — keep a vetted library");
    else if (verdict.verdict === "reimplement") reasons.push("tiny, likely reimplementable");
    else if (verdict.verdict === "keep") reasons.push("non-trivial to replace");

    return {
      name,
      version,
      usedBy: [...u.usedBy].sort(),
      usageCount: u.usedBy.size,
      dev: u.devOnly,
      unpackedSize,
      transitiveDeps: tree.deps,
      footprintBytes: tree.bytes,
      footprintApprox: !tree.complete,
      sensitive: sensitiveHits.length > 0,
      verdict: verdict.verdict,
      reimplementScore,
      commonsScore,
      reasons,
    } satisfies CommonDep;
  });

  const ranked = deps.filter((d): d is CommonDep => d !== null);
  ranked.sort(
    (a, b) =>
      b.commonsScore - a.commonsScore ||
      b.usageCount - a.usageCount ||
      a.name.localeCompare(b.name),
  );

  return {
    packages: manifests.map((m) => m.name),
    deps: ranked,
    generatedAt: new Date().toISOString(),
  };
}
