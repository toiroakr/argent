import { getJson } from "../http.js";
import { footprintOf, makeRegistry } from "../npm.js";
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

export interface BuildVsBuyMetrics {
  /** Unpacked size of the published tarball, in bytes. */
  unpackedSize?: number;
  fileCount?: number;
  directDeps?: number;
  /** Total transitive dependencies (resolved graph size minus the package). */
  transitiveDeps?: number;
  /** Sensitive-domain terms found in name/keywords/description. */
  sensitiveHits: string[];
}

export interface BuildVsBuyVerdict {
  level: RiskLevel;
  verdict: "reimplement" | "consider" | "keep" | "unknown";
  recommendation: string;
}

const KB = 1024;

/**
 * Pure build-vs-buy heuristic: should you take this dependency, or is it small
 * and mundane enough to reimplement (e.g. with AI) and avoid the supply-chain
 * cost? Security-sensitive domains always lean "keep a vetted library".
 *
 * The returned `level` is an ADOPTION signal, not a security severity:
 *   high   → strong candidate to drop the dep and reimplement
 *   medium → worth considering vendoring / an AI-assisted reimplementation
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

  // Need at least one size signal to judge; otherwise stay neutral.
  if (m.unpackedSize === undefined && m.transitiveDeps === undefined) {
    return {
      level: "unknown",
      verdict: "unknown",
      recommendation: "Not enough size/dependency data to judge reimplementability.",
    };
  }

  const transitive = m.transitiveDeps ?? m.directDeps ?? 0;
  const size = m.unpackedSize;
  const files = m.fileCount;

  const trivial =
    transitive <= 2 &&
    size !== undefined &&
    size <= 50 * KB &&
    (files === undefined || files <= 12);

  if (trivial) {
    return {
      level: "high",
      verdict: "reimplement",
      recommendation:
        "Tiny package — likely reimplementable (e.g. with AI), shedding it and its few deps. Weigh that against the supply-chain cost of the dependency.",
    };
  }

  const small =
    transitive <= 6 && size !== undefined && size <= 256 * KB;

  if (small) {
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
  nodes?: { versionKey: { name: string; version: string }; relation?: string }[];
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
      const transitiveDeps = nodes.length ? Math.max(0, nodes.length - 1) : undefined;

      // Install footprint: own + every transitive dep's unpacked size.
      const footprint = nodes.length
        ? await footprintOf(
            nodes.map((n) => n.versionKey),
            registry,
          )
        : undefined;

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
        transitiveDeps,
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
      if (transitiveDeps !== undefined)
        findings.push({
          label: "Transitive dependencies",
          value: String(transitiveDeps),
        });
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
