import { getJson } from "./http.js";
import {
  findSensitiveTerms,
  recommendBuildVsBuy,
  type BuildVsBuyVerdict,
} from "./providers/reimplementability.js";
import { aggregate, levelFromSeverity } from "./risk.js";
import type { RiskLevel } from "./types.js";

const REGISTRY = "https://registry.npmjs.org";
const DEPSDEV = "https://api.deps.dev/v3";

export interface DepAudit {
  name: string;
  version: string;
  /** True when the package depends on this directly (vs. only transitively). */
  direct: boolean;
  /** Transitive dependencies this package itself pulls in (within this graph). */
  transitiveDeps: number;
  unpackedSize?: number;
  advisoryCount: number;
  /** Worst advisory severity (or "low" when clean, "unknown" on lookup error). */
  severity: RiskLevel;
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

/** How easy/worthwhile it is to remove the dependency (0-100). */
function removability(verdict: DepAudit["verdict"], sensitive: boolean): number {
  if (sensitive) return 5;
  switch (verdict) {
    case "reimplement":
      return 100;
    case "consider":
      return 60;
    case "keep":
      return 15;
    default:
      return 40;
  }
}

/**
 * dropScore weights actual risk against how removable the dependency is, so the
 * top of the ranking is "risky AND realistic to drop" — the most actionable
 * wins for improving the parent package's supply-chain posture.
 *
 * `severityScore` is the numeric risk contribution (0 when the dependency has
 * no advisories, even though its display level is "low").
 */
export function scoreDrop(
  severityScore: number,
  verdict: DepAudit["verdict"],
  sensitive: boolean,
): number {
  return Math.round(0.55 * severityScore + 0.45 * removability(verdict, sensitive));
}

interface GraphNode {
  versionKey: { name: string; version: string };
  relation?: "SELF" | "DIRECT" | "INDIRECT";
}
interface Graph {
  nodes?: GraphNode[];
  edges?: { fromNode: number; toNode: number }[];
}

interface RegistryDoc {
  description?: string;
  keywords?: string[];
  versions: Record<
    string,
    {
      dependencies?: Record<string, string>;
      keywords?: string[];
      dist?: { unpackedSize?: number; fileCount?: number };
    }
  >;
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

/** Counts nodes reachable from `start` (excluding itself) over the dep graph. */
function transitiveCount(adj: Map<number, number[]>, start: number): number {
  const seen = new Set<number>();
  const stack = [...(adj.get(start) ?? [])];
  while (stack.length) {
    const n = stack.pop()!;
    if (n === start || seen.has(n)) continue;
    seen.add(n);
    for (const m of adj.get(n) ?? []) stack.push(m);
  }
  return seen.size;
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
  fetchImpl: typeof fetch,
): Promise<{ verdict: DepAudit["verdict"]; sensitive: boolean; unpackedSize?: number }> {
  const reg = await getJson<RegistryDoc>(
    `${REGISTRY}/${encodeURIComponent(name)}`,
    { fetch: fetchImpl },
  ).catch(() => undefined);
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
  return { verdict: verdict.verdict, sensitive: sensitiveHits.length > 0, unpackedSize };
}

function buildReasons(d: Omit<DepAudit, "reasons" | "dropScore">): string[] {
  const reasons: string[] = [];
  if (d.advisoryCount > 0)
    reasons.push(`${d.advisoryCount} advisory(ies), ${d.severity} severity`);
  if (d.sensitive) reasons.push("security-sensitive — hard to drop safely");
  else if (d.verdict === "reimplement") reasons.push("tiny, likely reimplementable");
  else if (d.verdict === "consider") reasons.push("fairly small, vendorable");
  else if (d.verdict === "keep") reasons.push("non-trivial to replace");
  if (d.transitiveDeps > 0)
    reasons.push(`pulls ${d.transitiveDeps} transitive dep(s)`);
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

  const graph = await getJson<Graph>(
    `${DEPSDEV}/systems/npm/packages/${encodeURIComponent(name)}/versions/${encodeURIComponent(version)}:dependencies`,
    { fetch: fetchImpl },
  );
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

  const ranking = await mapLimit(
    limited,
    options.concurrency ?? 8,
    async ({ node, index }): Promise<DepAudit> => {
      const depName = node.versionKey.name;
      const depVersion = node.versionKey.version;
      const transitiveDeps = transitiveCount(adj, index);

      const [risk, reimpl] = await Promise.all([
        depRisk(depName, depVersion, fetchImpl),
        depReimpl(depName, depVersion, transitiveDeps, fetchImpl),
      ]);

      const partial: Omit<DepAudit, "reasons" | "dropScore"> = {
        name: depName,
        version: depVersion,
        direct: node.relation === "DIRECT",
        transitiveDeps,
        unpackedSize: reimpl.unpackedSize,
        advisoryCount: risk.count,
        severity: risk.level,
        verdict: reimpl.verdict,
        sensitive: reimpl.sensitive,
      };
      // Clean deps contribute no risk even though their display level is "low".
      const severityScore = risk.count === 0 ? 0 : SEVERITY_SCORE[risk.level];
      const score = scoreDrop(severityScore, reimpl.verdict, reimpl.sensitive);
      return { ...partial, dropScore: score, reasons: buildReasons(partial) };
    },
  );

  ranking.sort(
    (a, b) =>
      b.dropScore - a.dropScore ||
      SEVERITY_SCORE[b.severity] - SEVERITY_SCORE[a.severity] ||
      a.name.localeCompare(b.name),
  );

  return {
    target: { name, version },
    totalDependencies: total,
    evaluated: limited.length,
    ranking,
    generatedAt: new Date().toISOString(),
  };
}
