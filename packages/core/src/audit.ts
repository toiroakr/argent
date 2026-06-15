import { getJson } from "./http.js";
import { makeRegistry, type RegistryClient } from "./npm.js";
import {
  findSensitiveTerms,
  recommendBuildVsBuy,
  type BuildVsBuyVerdict,
} from "./providers/reimplementability.js";
import { INSTALL_HOOKS } from "./providers/supplychain.js";
import { aggregate, levelFromSeverity } from "./risk.js";
import type { RiskLevel } from "./types.js";

const DEPSDEV = "https://api.deps.dev/v3";

export interface DepAudit {
  name: string;
  version: string;
  /** True when the package depends on this directly (vs. only transitively). */
  direct: boolean;
  /** True when this came from devDependencies (manifest audit only). */
  dev?: boolean;
  /** Transitive deps this dependency *exclusively* pulls (shared ones excluded). */
  transitiveDeps: number;
  /** Total transitive deps in its resolved subtree (incl. shared ones). */
  totalDeps?: number;
  /** The package's own unpacked size (its code only). */
  unpackedSize?: number;
  /**
   * Exclusive install footprint in bytes: own size + the unpacked size of every
   * package that is only reachable through this dependency. Packages shared with
   * other deps are excluded, because dropping this one wouldn't remove them.
   */
  footprintBytes?: number;
  /** True when some subtree sizes were unknown, so footprintBytes is a floor. */
  footprintApprox?: boolean;
  /** Total subtree install size in bytes, incl. shared deps (informational). */
  totalFootprintBytes?: number;
  /** True when some subtree sizes were unknown, so totalFootprintBytes is a floor. */
  totalFootprintApprox?: boolean;
  advisoryCount: number;
  /** Worst advisory severity (or "low" when clean, "unknown" on lookup error). */
  severity: RiskLevel;
  /** The dependency is deprecated on npm — a strong reason to replace it. */
  deprecated?: boolean;
  /** Runs an install lifecycle script (preinstall/install/postinstall). */
  installScript?: boolean;
  verdict: BuildVsBuyVerdict["verdict"];
  sensitive: boolean;
  /** 0-100; higher = stronger candidate to drop to improve the parent. */
  dropScore: number;
  reasons: string[];
}

export interface AuditReport {
  target: { name: string; version: string };
  /** Total dependencies discovered in the resolved graph. */
  totalDependencies: number;
  /** How many were actually evaluated (may be capped by maxDeps). */
  evaluated: number;
  /** Dependencies ranked by dropScore, descending. */
  ranking: DepAudit[];
  generatedAt: string;
}

export interface AuditOptions {
  version?: string;
  fetch?: typeof fetch;
  /** Only audit direct dependencies. */
  directOnly?: boolean;
  /** Cap on how many dependencies to evaluate (default 250). */
  maxDeps?: number;
  /** Parallel lookups (default 8). */
  concurrency?: number;
}

const SEVERITY_SCORE: Record<RiskLevel, number> = {
  critical: 100,
  high: 75,
  medium: 50,
  low: 25,
  unknown: 0,
};

const clamp01 = (x: number): number => Math.max(0, Math.min(1, x));

/** Maps `v` to 0..1 on a log scale between `lo` and `hi`. */
function logScale(v: number, lo: number, hi: number): number {
  if (v <= lo) return 0;
  return clamp01((Math.log10(v) - Math.log10(lo)) / (Math.log10(hi) - Math.log10(lo)));
}

export interface DropInputs {
  sensitive: boolean;
  /** The dependency's own unpacked size in bytes. */
  ownBytes?: number;
  /** Install footprint incl. transitive deps, in bytes. */
  footprintBytes?: number;
  transitiveDeps: number;
}

/**
 * dropScore (0-100): an ADOPTION signal — how cheaply and worthwhile it is to
 * actually escape this dependency, ignoring vulnerabilities (those are a
 * separate axis: deps with advisories are surfaced first and shown in their own
 * column, not blended in here).
 *
 * A dependency is realistically droppable when it is **small AND self-contained**
 * — a few lines of mundane code you can just inline. A large dependency subtree
 * works *against* this: a thin wrapper over a big tree isn't easy to drop, because
 * removing the package still leaves you needing the functionality its tree
 * provides (so the "weight you'd shed" is usually illusory). So both the
 * transitive dep count and the install footprint LOWER the score.
 *
 *   - own code small        → inline-able
 *   - few/no transitive deps → self-contained, nothing to re-expand
 *   - small install footprint → little real functionality delegated
 */
export function scoreDrop(i: DropInputs): number {
  // Reimplementing security-sensitive code is a bad idea regardless of size.
  if (i.sensitive) return 10;

  const ownFactor =
    i.ownBytes === undefined ? 0.5 : 1 - logScale(i.ownBytes, 2_000, 500_000); // 2KB→1, 500KB→0
  const selfContained = 1 - clamp01(i.transitiveDeps / 8); // 0 deps→1, 8+→0
  const lightFactor =
    i.footprintBytes === undefined
      ? ownFactor
      : 1 - logScale(i.footprintBytes, 10_000, 2_000_000); // 10KB→1, 2MB→0

  const ease = clamp01(0.4 * ownFactor + 0.35 * selfContained + 0.25 * lightFactor);
  return Math.round(100 * ease);
}

interface GraphNode {
  versionKey: { name: string; version: string };
  relation?: "SELF" | "DIRECT" | "INDIRECT";
}
interface Graph {
  nodes?: GraphNode[];
  edges?: { fromNode: number; toNode: number }[];
}

async function resolveVersion(
  name: string,
  requested: string | undefined,
  fetchImpl: typeof fetch,
): Promise<string> {
  if (requested) return requested;
  const pkg = await getJson<{
    versions?: { versionKey: { version: string }; isDefault?: boolean }[];
  }>(`${DEPSDEV}/systems/npm/packages/${encodeURIComponent(name)}`, {
    fetch: fetchImpl,
  });
  const versions = pkg.versions ?? [];
  const def = versions.find((v) => v.isDefault) ?? versions.at(-1);
  if (!def) throw new Error(`No versions found for ${name}`);
  return def.versionKey.version;
}

/**
 * Nodes reachable from `from`, never traversing into `blocked` (-1 = nothing
 * blocked). The returned set includes `from`. Used to find which nodes a
 * dependency *exclusively* pulls: nodes reachable normally but not when its
 * node is blocked are the ones only it brings in (its dominator set).
 */
function reachableAvoiding(
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

async function mapLimit<T, R>(
  items: T[],
  limit: number,
  fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const out = new Array<R>(items.length);
  let cursor = 0;
  const workers = Array.from(
    { length: Math.max(1, Math.min(limit, items.length)) },
    async () => {
      while (true) {
        const i = cursor++;
        if (i >= items.length) break;
        out[i] = await fn(items[i]!, i);
      }
    },
  );
  await Promise.all(workers);
  return out;
}

async function depRisk(
  name: string,
  version: string,
  fetchImpl: typeof fetch,
): Promise<{ level: RiskLevel; count: number }> {
  try {
    const ver = await getJson<{ advisoryKeys?: { id: string }[] }>(
      `${DEPSDEV}/systems/npm/packages/${encodeURIComponent(name)}/versions/${encodeURIComponent(version)}`,
      { fetch: fetchImpl },
    );
    const keys = ver.advisoryKeys ?? [];
    if (keys.length === 0) return { level: "low", count: 0 };
    const sevs = await Promise.all(
      keys.map((k) =>
        getJson<{ severity?: string }>(
          `${DEPSDEV}/advisories/${encodeURIComponent(k.id)}`,
          { fetch: fetchImpl },
        ).catch(() => ({}) as { severity?: string }),
      ),
    );
    return {
      level: aggregate(sevs.map((s) => levelFromSeverity(s.severity))),
      count: keys.length,
    };
  } catch {
    return { level: "unknown", count: 0 };
  }
}

async function depReimpl(
  name: string,
  version: string,
  transitiveDeps: number,
  registry: RegistryClient,
): Promise<{
  verdict: DepAudit["verdict"];
  sensitive: boolean;
  unpackedSize?: number;
  deprecated: boolean;
  installScript: boolean;
}> {
  const reg = await registry.doc(name);
  const v = reg?.versions?.[version];
  const unpackedSize = v?.dist?.unpackedSize;
  const fileCount = v?.dist?.fileCount;
  const directDeps = v?.dependencies ? Object.keys(v.dependencies).length : undefined;
  const keywords = reg?.keywords ?? v?.keywords ?? [];
  const sensitiveHits = findSensitiveTerms(name, keywords, reg?.description ?? "");
  const verdict = recommendBuildVsBuy({
    unpackedSize,
    fileCount,
    directDeps,
    transitiveDeps,
    sensitiveHits,
  });
  return {
    verdict: verdict.verdict,
    sensitive: sensitiveHits.length > 0,
    unpackedSize,
    deprecated: typeof v?.deprecated === "string",
    installScript: INSTALL_HOOKS.some((h) => v?.scripts?.[h]),
  };
}

function humanBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function buildReasons(d: Omit<DepAudit, "reasons" | "dropScore">): string[] {
  const reasons: string[] = [];
  if (d.deprecated) reasons.push("deprecated — replace it");
  if (d.advisoryCount > 0)
    reasons.push(`${d.advisoryCount} advisory(ies), ${d.severity} severity`);
  if (d.installScript) reasons.push("runs install scripts");
  if (d.sensitive) reasons.push("security-sensitive — hard to drop safely");
  else if (d.verdict === "reimplement") reasons.push("tiny, likely reimplementable");
  else if (d.verdict === "consider") reasons.push("fairly small, vendorable");
  else if (d.verdict === "keep") reasons.push("non-trivial to replace");
  if (d.transitiveDeps > 0) {
    const fp =
      d.footprintBytes !== undefined
        ? `, ~${humanBytes(d.footprintBytes)}${d.footprintApprox ? "+" : ""}`
        : "";
    reasons.push(`uniquely pulls ${d.transitiveDeps} dep(s)${fp}`);
  }
  return reasons;
}

/**
 * Audits every dependency of a package and ranks them by how worthwhile it is
 * to drop each one (escape it) to improve the package's supply-chain posture.
 * Combines deps.dev advisories with the Build-vs-Buy reimplementability signal.
 */
export async function auditDependencies(
  name: string,
  options: AuditOptions = {},
): Promise<AuditReport> {
  const fetchImpl = options.fetch ?? globalThis.fetch;
  if (!fetchImpl) throw new Error("No fetch implementation available");

  const version = await resolveVersion(name, options.version, fetchImpl);

  // deps.dev doesn't have a resolved graph for every package (e.g. some scoped
  // or private-registry-published ones return 404). Fall back to auditing the
  // direct dependencies declared in the npm manifest instead of failing.
  const graph = await getJson<Graph>(
    `${DEPSDEV}/systems/npm/packages/${encodeURIComponent(name)}/versions/${encodeURIComponent(version)}:dependencies`,
    { fetch: fetchImpl },
  ).catch(() => undefined);

  if (!graph || !(graph.nodes ?? []).length) {
    return auditFromManifest(name, version, fetchImpl, options);
  }

  const nodes = graph.nodes ?? [];

  const adj = new Map<number, number[]>();
  for (const e of graph.edges ?? []) {
    const list = adj.get(e.fromNode) ?? [];
    list.push(e.toNode);
    adj.set(e.fromNode, list);
  }

  const deps = nodes
    .map((node, index) => ({ node, index }))
    .filter(({ node }) => node.relation && node.relation !== "SELF")
    .filter(({ node }) => !options.directOnly || node.relation === "DIRECT");

  const total = deps.length;
  const maxDeps = options.maxDeps ?? 250;
  const limited = deps.slice(0, maxDeps);
  const registry = makeRegistry(fetchImpl);

  const root = Math.max(0, nodes.findIndex((n) => n.relation === "SELF"));
  const allReachable = reachableAvoiding(adj, root, -1);
  // Prefetch every node's unpacked size once (registry cache dedupes by name).
  const nodeBytes = await mapLimit(nodes, options.concurrency ?? 8, (n) =>
    registry.size(n.versionKey.name, n.versionKey.version),
  );

  const ranking = await mapLimit(
    limited,
    options.concurrency ?? 8,
    ({ node, index }): Promise<DepAudit> => {
      // Exclusive footprint: nodes that become unreachable from the root when
      // this dep is blocked — i.e. what it *uniquely* pulls. Shared deps (still
      // reachable via others) are excluded, since dropping this one wouldn't
      // remove them anyway.
      const without = reachableAvoiding(adj, root, index);
      let bytes = 0;
      let complete = true;
      let exclusiveDeps = 0;
      for (const i of allReachable) {
        if (without.has(i)) continue;
        if (i !== index) exclusiveDeps++;
        const b = nodeBytes[i];
        if (typeof b === "number") bytes += b;
        else complete = false;
      }
      // Total subtree (incl. shared deps), for the JSON detail.
      const sub = reachableAvoiding(adj, index, -1);
      let totalBytes = 0;
      let totalComplete = true;
      for (const i of sub) {
        const b = nodeBytes[i];
        if (typeof b === "number") totalBytes += b;
        else totalComplete = false;
      }
      return assembleDep(
        {
          name: node.versionKey.name,
          version: node.versionKey.version,
          direct: node.relation === "DIRECT",
        },
        exclusiveDeps,
        { bytes, complete },
        registry,
        fetchImpl,
        { deps: sub.size - 1, footprint: { bytes: totalBytes, complete: totalComplete } },
      );
    },
  );

  sortRanking(ranking);

  return {
    target: { name, version },
    totalDependencies: total,
    evaluated: limited.length,
    ranking,
    generatedAt: new Date().toISOString(),
  };
}

/**
 * Fallback when deps.dev has no resolved graph: audit the direct dependencies
 * declared in the package's own npm manifest (versions resolved to latest).
 */
async function auditFromManifest(
  name: string,
  version: string,
  fetchImpl: typeof fetch,
  options: AuditOptions,
): Promise<AuditReport> {
  const registry = makeRegistry(fetchImpl);
  const doc = await registry.doc(name);
  const deps = doc?.versions?.[version]?.dependencies ?? {};
  const entries: AuditEntry[] = Object.keys(deps).map((n) => ({ name: n }));
  const report = await auditEntries({ name, version }, entries, {
    fetch: fetchImpl,
    maxDeps: options.maxDeps,
    concurrency: options.concurrency,
  });
  // totalDependencies here reflects direct deps only (no transitive graph).
  return report;
}

function sortRanking(ranking: DepAudit[]): void {
  // Advisories and deprecations are separate, urgent axes: deps carrying either
  // float to the top, then the rest rank by dropScore.
  const urgent = (d: DepAudit) => (d.advisoryCount > 0 || d.deprecated ? 1 : 0);
  ranking.sort(
    (a, b) =>
      urgent(b) - urgent(a) ||
      SEVERITY_SCORE[b.severity] - SEVERITY_SCORE[a.severity] ||
      (b.deprecated ? 1 : 0) - (a.deprecated ? 1 : 0) ||
      b.dropScore - a.dropScore ||
      a.name.localeCompare(b.name),
  );
}

interface Footprint {
  bytes: number;
  complete: boolean;
}

/** Builds a single DepAudit from the risk + reimplementability lookups. */
async function assembleDep(
  entry: { name: string; version: string; direct: boolean; dev?: boolean },
  transitiveDeps: number,
  footprint: Footprint | undefined,
  registry: RegistryClient,
  fetchImpl: typeof fetch,
  total?: { deps: number; footprint: Footprint },
): Promise<DepAudit> {
  const [risk, reimpl] = await Promise.all([
    depRisk(entry.name, entry.version, fetchImpl),
    depReimpl(entry.name, entry.version, transitiveDeps, registry),
  ]);

  const partial: Omit<DepAudit, "reasons" | "dropScore"> = {
    name: entry.name,
    version: entry.version,
    direct: entry.direct,
    dev: entry.dev,
    transitiveDeps,
    totalDeps: total?.deps,
    unpackedSize: reimpl.unpackedSize,
    footprintBytes: footprint?.bytes,
    footprintApprox: footprint ? !footprint.complete : undefined,
    totalFootprintBytes: total?.footprint.bytes,
    totalFootprintApprox: total ? !total.footprint.complete : undefined,
    advisoryCount: risk.count,
    severity: risk.level,
    deprecated: reimpl.deprecated,
    installScript: reimpl.installScript,
    verdict: reimpl.verdict,
    sensitive: reimpl.sensitive,
  };
  const score = scoreDrop({
    sensitive: reimpl.sensitive,
    ownBytes: reimpl.unpackedSize,
    footprintBytes: footprint?.bytes,
    transitiveDeps,
  });
  return { ...partial, dropScore: score, reasons: buildReasons(partial) };
}

/** Fetches a single package's resolved dependency graph nodes (self included). */
async function depGraphNodes(
  name: string,
  version: string,
  fetchImpl: typeof fetch,
): Promise<GraphNode[]> {
  try {
    const graph = await getJson<Graph>(
      `${DEPSDEV}/systems/npm/packages/${encodeURIComponent(name)}/versions/${encodeURIComponent(version)}:dependencies`,
      { fetch: fetchImpl },
    );
    return graph.nodes ?? [];
  } catch {
    return [];
  }
}

export interface AuditEntry {
  name: string;
  /** Resolved version; when omitted the default version is resolved. */
  version?: string;
  dev?: boolean;
}

/**
 * Audits an explicit list of dependencies (e.g. from a local package.json),
 * ranking them the same way as {@link auditDependencies}. Each entry is treated
 * as a direct dependency; its own transitive footprint is fetched per package.
 */
export async function auditEntries(
  target: { name: string; version: string },
  entries: AuditEntry[],
  options: Omit<AuditOptions, "version" | "directOnly"> = {},
): Promise<AuditReport> {
  const fetchImpl = options.fetch ?? globalThis.fetch;
  if (!fetchImpl) throw new Error("No fetch implementation available");

  const maxDeps = options.maxDeps ?? 250;
  const limited = entries.slice(0, maxDeps);
  const registry = makeRegistry(fetchImpl);
  const concurrency = options.concurrency ?? 8;
  const id = (k: { name: string; version: string }) => `${k.name}@${k.version}`;

  // Phase 1: resolve each entry and fetch its full subtree.
  const resolved = await mapLimit(limited, concurrency, async (entry) => {
    try {
      const version =
        entry.version ?? (await resolveVersion(entry.name, undefined, fetchImpl));
      const nodes = await depGraphNodes(entry.name, version, fetchImpl);
      const keys = nodes.length
        ? nodes.map((n) => n.versionKey)
        : [{ name: entry.name, version }];
      return { entry, version, keys };
    } catch {
      return null;
    }
  });

  // Count how many direct deps' subtrees each package appears in — packages
  // shared across deps are installed anyway, so they don't count as "shed".
  // Production deps are counted against the production graph only (sharing with
  // a devDependency doesn't matter for a shipped install); devDeps against all.
  const countOver = (predicate: (dev: boolean) => boolean) => {
    const m = new Map<string, number>();
    for (const r of resolved) {
      if (!r || !predicate(!!r.entry.dev)) continue;
      for (const k of new Set(r.keys.map(id))) m.set(k, (m.get(k) ?? 0) + 1);
    }
    return m;
  };
  const prodShared = countOver((dev) => !dev);
  const allShared = countOver(() => true);

  // Phase 2: score each entry by its EXCLUSIVE footprint (packages only it pulls).
  const results = await mapLimit(resolved, concurrency, async (r): Promise<DepAudit | null> => {
    if (!r) return null;
    const ownId = id({ name: r.entry.name, version: r.version });
    const shared = r.entry.dev ? allShared : prodShared;
    const uniqueKeys = [...new Map(r.keys.map((k) => [id(k), k])).values()];
    const sumSizes = async (keys: { name: string; version: string }[]) => {
      const sizes = await Promise.all(keys.map((k) => registry.size(k.name, k.version)));
      let bytes = 0;
      let complete = true;
      for (const s of sizes) {
        if (typeof s === "number") bytes += s;
        else complete = false;
      }
      return { bytes, complete };
    };
    const exclusive = uniqueKeys.filter((k) => (shared.get(id(k)) ?? 0) <= 1);
    const [excl, tot] = await Promise.all([sumSizes(exclusive), sumSizes(uniqueKeys)]);
    const exclusiveDeps = exclusive.filter((k) => id(k) !== ownId).length;
    return assembleDep(
      { name: r.entry.name, version: r.version, direct: true, dev: r.entry.dev },
      exclusiveDeps,
      excl,
      registry,
      fetchImpl,
      { deps: uniqueKeys.length - 1, footprint: tot },
    );
  });

  const ranking = results.filter((r): r is DepAudit => r !== null);
  sortRanking(ranking);

  return {
    target,
    totalDependencies: entries.length,
    evaluated: ranking.length,
    ranking,
    generatedAt: new Date().toISOString(),
  };
}
