import { buildAdjacency, reachableAvoiding } from "../graph.js";
import { getJson } from "../http.js";
import { footprintOf, makeRegistry, mapLimit, sumSizes } from "../npm.js";
import type { Provider, ProviderFinding, ProviderResult, RiskLevel } from "../types.js";

const DEPSDEV = "https://api.deps.dev/v3";

/**
 * Domains where rolling your own (or an AI-generated) implementation is risky
 * regardless of how small the package looks. Getting these subtly wrong has
 * security consequences, so a vetted library is usually the right call.
 * Matched as whole words against the package name, keywords and description.
 */
const SENSITIVE_TERMS = [
  "crypto", "cryptography", "encryption", "encrypt", "decrypt", "cipher",
  "hash", "hashing", "bcrypt", "scrypt", "argon2", "pbkdf2", "md5", "sha1",
  "sha256", "hmac", "rsa", "aes", "ecdsa", "ed25519",
  "password", "passwd", "secret", "credential", "credentials",
  "jwt", "jsonwebtoken", "oauth", "oauth2", "openid", "saml",
  "auth", "authentication", "authorization", "login", "session",
  "token", "csrf", "xss", "sanitize", "sanitizer", "sanitization",
  "escape-html", "sql", "injection",
  "tls", "ssl", "https", "certificate", "x509",
  "random", "prng", "csprng", "uuid", "nanoid", "entropy", "secure-random",
  "signature", "signing", "keypair", "private-key", "public-key",
];

/** A single direct dependency's exclusive install footprint. */
export interface DirectDepWeight {
  name: string;
  version: string;
  /** Bytes only reachable through this direct dependency (shared deps excluded). */
  footprintBytes?: number;
  /** True when some subtree sizes were unknown, so footprintBytes is a floor. */
  footprintApprox?: boolean;
}

export interface BuildVsBuyMetrics {
  /** Unpacked size of the published tarball, in bytes. */
  unpackedSize?: number;
  fileCount?: number;
  /** Declared direct dependency count; used only when no richer signal is available. */
  directDeps?: number;
  /**
   * Aggregate transitive/exclusive dependency count, used when there's no
   * per-dependency weight breakdown (e.g. auditing a single dependency node
   * deep inside a larger graph, where recursing per-child isn't worth it).
   */
  transitiveDeps?: number;
  /**
   * Per-direct-dependency exclusive weight. When present, this drives a finer
   * verdict: a package can be thin itself yet depend on one heavy library —
   * that's "partial" (reimplement the wrapper, keep the heavy dependency),
   * distinct from "every direct dependency is heavy" (keep the whole thing).
   */
  directDepWeights?: DirectDepWeight[];
  /** Sensitive-domain terms found in name/keywords/description. */
  sensitiveHits: string[];
}

export interface BuildVsBuyVerdict {
  level: RiskLevel;
  verdict: "reimplement" | "consider" | "partial" | "keep" | "unknown";
  recommendation: string;
  /** Present only for "partial": the direct dependencies worth keeping as-is. */
  keepDeps?: string[];
}

const KB = 1024;
const BODY_TRIVIAL_BYTES = 50 * KB;
const BODY_TRIVIAL_FILES = 12;
const BODY_SMALL_BYTES = 256 * KB;
/** A direct dependency whose exclusive footprint exceeds this is "heavy". */
const DEP_HEAVY_BYTES = 256 * KB;
const LIGHT_DEP_TRIVIAL_LIMIT = 2;
const LIGHT_DEP_SMALL_LIMIT = 6;

/**
 * Pure build-vs-buy heuristic: should you take this dependency, or is it small
 * and mundane enough to reimplement (e.g. with AI) and avoid the supply-chain
 * cost? Security-sensitive domains always lean "keep a vetted library".
 *
 * The returned `level` is an ADOPTION signal, not a security severity:
 *   high   → strong candidate to drop the dep and reimplement
 *   medium → worth considering vendoring / an AI-assisted reimplementation,
 *            or (verdict "partial") reimplementing everything except one or
 *            two genuinely heavy direct dependencies
 *   low    → keep the dependency (sensitive or non-trivial)
 */
export function recommendBuildVsBuy(m: BuildVsBuyMetrics): BuildVsBuyVerdict {
  if (m.sensitiveHits.length > 0) {
    return {
      level: "low",
      verdict: "keep",
      recommendation: `Security-sensitive domain (${m.sensitiveHits
        .slice(0, 4)
        .join(", ")}); prefer a well-reviewed library over a custom/AI implementation.`,
    };
  }

  const haveBody = m.unpackedSize !== undefined;
  const haveWeights = m.directDepWeights !== undefined;
  const haveCount = m.transitiveDeps !== undefined || m.directDeps !== undefined;
  if (!haveBody && !haveWeights && !haveCount) {
    return {
      level: "unknown",
      verdict: "unknown",
      recommendation: "Not enough size/dependency data to judge reimplementability.",
    };
  }

  const bodyTrivial =
    haveBody &&
    m.unpackedSize! <= BODY_TRIVIAL_BYTES &&
    (m.fileCount === undefined || m.fileCount <= BODY_TRIVIAL_FILES);
  const bodySmall = haveBody && m.unpackedSize! <= BODY_SMALL_BYTES;

  // Richer path: judge the package's own code separately from each direct
  // dependency's actual weight, instead of blending everything into one
  // transitive-count threshold.
  if (haveWeights) {
    const weights = m.directDepWeights!;
    const heavy = weights.filter((d) => (d.footprintBytes ?? 0) > DEP_HEAVY_BYTES);
    const light = weights.filter((d) => (d.footprintBytes ?? 0) <= DEP_HEAVY_BYTES);
    const allLight = heavy.length === 0;
    const mixed = heavy.length > 0 && heavy.length < weights.length;

    if (allLight && bodyTrivial && light.length <= LIGHT_DEP_TRIVIAL_LIMIT) {
      return {
        level: "high",
        verdict: "reimplement",
        recommendation:
          "Tiny package with only lightweight direct dependencies — likely reimplementable (e.g. with AI), shedding it and them. Weigh that against the supply-chain cost of the dependency.",
      };
    }

    if (mixed && (bodyTrivial || bodySmall) && weights.length <= LIGHT_DEP_SMALL_LIMIT) {
      const heavyNames = heavy.map((d) => d.name);
      return {
        level: "medium",
        verdict: "partial",
        keepDeps: heavyNames,
        recommendation: `Own code is thin and ${light.length} of ${weights.length} direct dependencies are lightweight — consider reimplementing the wrapper yourself while keeping a direct dependency on ${heavyNames.join(", ")} rather than also replacing it.`,
      };
    }

    if (allLight && bodySmall && light.length <= LIGHT_DEP_SMALL_LIMIT) {
      return {
        level: "medium",
        verdict: "consider",
        recommendation:
          "Fairly small with lightweight dependencies — vendoring or an AI-assisted reimplementation may be reasonable; compare maintenance burden vs. supply-chain risk.",
      };
    }

    return {
      level: "low",
      verdict: "keep",
      recommendation:
        "Depends on non-trivial (heavy) dependencies, or has too many of them to treat as self-contained — reimplementing is likely not worth it; keep the dependency.",
    };
  }

  // Coarser path: only an aggregate dependency count is known (no per-dependency
  // breakdown — e.g. this package is itself one node deep inside a larger audit).
  const count = m.transitiveDeps ?? m.directDeps ?? 0;

  if (bodyTrivial && count <= LIGHT_DEP_TRIVIAL_LIMIT) {
    return {
      level: "high",
      verdict: "reimplement",
      recommendation:
        "Tiny package — likely reimplementable (e.g. with AI), shedding it and its few deps. Weigh that against the supply-chain cost of the dependency.",
    };
  }

  if (bodySmall && count <= LIGHT_DEP_SMALL_LIMIT) {
    return {
      level: "medium",
      verdict: "consider",
      recommendation:
        "Fairly small — vendoring or an AI-assisted reimplementation may be reasonable; compare maintenance burden vs. supply-chain risk.",
    };
  }

  return {
    level: "low",
    verdict: "keep",
    recommendation:
      "Non-trivial size or dependency graph — reimplementing is likely not worth it; keep the dependency.",
  };
}

export function findSensitiveTerms(
  name: string,
  keywords: string[],
  description: string,
): string[] {
  const haystack = [name, ...keywords, description].join(" ").toLowerCase();
  const hits = new Set<string>();
  for (const term of SENSITIVE_TERMS) {
    const re = new RegExp(`\\b${term.replace(/[-]/g, "\\-")}\\b`);
    if (re.test(haystack)) hits.add(term);
  }
  return [...hits];
}

function humanSize(bytes: number): string {
  if (bytes < KB) return `${bytes} B`;
  if (bytes < KB * KB) return `${(bytes / KB).toFixed(1)} KB`;
  return `${(bytes / (KB * KB)).toFixed(1)} MB`;
}

interface DepsGraph {
  nodes?: {
    versionKey: { name: string; version: string };
    relation?: "SELF" | "DIRECT" | "INDIRECT";
  }[];
  edges?: { fromNode: number; toNode: number }[];
}

/**
 * For each direct dependency, the install footprint reachable ONLY through it
 * (shared subtrees are excluded, since dropping one dep wouldn't remove a
 * package still pulled in by another). This is what separates a package that
 * merely has a few direct deps from one that has a few *light* direct deps.
 */
async function weighDirectDeps(
  graph: DepsGraph,
  registry: ReturnType<typeof makeRegistry>,
): Promise<DirectDepWeight[] | undefined> {
  const nodes = graph.nodes ?? [];
  const rootIndex = nodes.findIndex((n) => n.relation === "SELF");
  if (!nodes.length || rootIndex < 0) return undefined;

  const directIndices = nodes
    .map((n, i) => ({ n, i }))
    .filter(({ n }) => n.relation === "DIRECT")
    .map(({ i }) => i);
  if (directIndices.length === 0) return [];

  const adj = buildAdjacency(graph.edges ?? []);
  const nodeBytes = await mapLimit(nodes, 8, (n) =>
    registry.size(n.versionKey.name, n.versionKey.version),
  );
  const allReachable = reachableAvoiding(adj, rootIndex, -1);

  return directIndices.map((di) => {
    const without = reachableAvoiding(adj, rootIndex, di);
    const exclusive = [...allReachable].filter((i) => !without.has(i));
    const { bytes, complete } = sumSizes(exclusive.map((i) => nodeBytes[i]));
    const node = nodes[di]!;
    return {
      name: node.versionKey.name,
      version: node.versionKey.version,
      footprintBytes: bytes,
      footprintApprox: !complete,
    };
  });
}

/**
 * Build-vs-buy adoption signal: combines npm registry size metrics and the
 * deps.dev resolved dependency graph with a domain-sensitivity check.
 * CORS-safe (registry.npmjs.org + api.deps.dev), so it runs in the browser too.
 */
export const reimplementabilityProvider: Provider = {
  id: "Build-vs-Buy",
  browserSafe: true,
  async evaluate(ctx): Promise<ProviderResult> {
    const url = `https://www.npmjs.com/package/${ctx.name}/v/${ctx.version}`;
    const base = { provider: "Build-vs-Buy", url, advisory: true };

    try {
      const registry = makeRegistry(ctx.fetch);
      const [reg, graph] = await Promise.all([
        registry.doc(ctx.name),
        getJson<DepsGraph>(
          `${DEPSDEV}/systems/npm/packages/${encodeURIComponent(ctx.name)}/versions/${encodeURIComponent(ctx.version)}:dependencies`,
          { fetch: ctx.fetch },
        ).catch(() => undefined),
      ]);

      const ver = reg?.versions?.[ctx.version];
      const unpackedSize = ver?.dist?.unpackedSize;
      const fileCount = ver?.dist?.fileCount;
      const directDeps = ver?.dependencies
        ? Object.keys(ver.dependencies).length
        : undefined;
      const nodes = graph?.nodes ?? [];
      const transitiveDepsTotal = nodes.length ? Math.max(0, nodes.length - 1) : undefined;

      const [footprint, directDepWeights] = await Promise.all([
        // Install footprint: own + every transitive dep's unpacked size.
        nodes.length ? footprintOf(nodes.map((n) => n.versionKey), registry) : undefined,
        graph ? weighDirectDeps(graph, registry) : undefined,
      ]);

      const keywords = reg?.keywords ?? ver?.keywords ?? [];
      const sensitiveHits = findSensitiveTerms(
        ctx.name,
        keywords,
        reg?.description ?? "",
      );

      const metrics: BuildVsBuyMetrics = {
        unpackedSize,
        fileCount,
        directDeps,
        directDepWeights,
        sensitiveHits,
      };
      const verdict = recommendBuildVsBuy(metrics);

      const findings: ProviderFinding[] = [];
      if (unpackedSize !== undefined)
        findings.push({ label: "Unpacked size", value: humanSize(unpackedSize) });
      if (fileCount !== undefined)
        findings.push({ label: "Files", value: String(fileCount) });
      if (directDeps !== undefined)
        findings.push({ label: "Direct dependencies", value: String(directDeps) });
      if (transitiveDepsTotal !== undefined)
        findings.push({
          label: "Transitive dependencies (total)",
          value: String(transitiveDepsTotal),
        });
      if (directDepWeights?.length) {
        const sorted = [...directDepWeights].sort(
          (a, b) => (b.footprintBytes ?? 0) - (a.footprintBytes ?? 0),
        );
        const shown = sorted.slice(0, 5);
        for (const d of shown) {
          findings.push({
            label: `↳ ${d.name}`,
            value:
              d.footprintBytes !== undefined
                ? `${humanSize(d.footprintBytes)}${d.footprintApprox ? "+" : ""} exclusive`
                : "size unknown",
            level: (d.footprintBytes ?? 0) > DEP_HEAVY_BYTES ? "medium" : "low",
          });
        }
        if (sorted.length > shown.length) {
          findings.push({
            label: "↳ …",
            value: `${sorted.length - shown.length} more direct dependency(ies)`,
          });
        }
      }
      if (footprint?.bytes !== undefined)
        findings.push({
          label: "Install size (with deps)",
          value: humanSize(footprint.bytes) + (footprint.complete ? "" : "+"),
        });
      if (sensitiveHits.length)
        findings.push({
          label: "Sensitive domain",
          value: sensitiveHits.slice(0, 5).join(", "),
          level: "low",
        });

      return {
        ...base,
        ok: true,
        level: verdict.level,
        summary: verdict.recommendation,
        findings,
      };
    } catch (err) {
      return {
        ...base,
        ok: false,
        level: "unknown",
        summary: "Build-vs-Buy assessment failed",
        findings: [],
        error: err instanceof Error ? err.message : String(err),
      };
    }
  },
};
