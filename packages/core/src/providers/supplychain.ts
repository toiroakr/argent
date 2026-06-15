import { getJson } from "../http.js";
import { REGISTRY, type RegistryDoc } from "../npm.js";
import type { Provider, ProviderFinding, ProviderResult, RiskLevel } from "../types.js";

/** npm lifecycle scripts that run on `npm install` — a classic malware vector. */
export const INSTALL_HOOKS = ["preinstall", "install", "postinstall"] as const;

/**
 * Integrity / supply-chain signals straight from the npm registry: whether the
 * package is deprecated, runs install scripts, ships build provenance, and how
 * many maintainers can publish it (bus factor / takeover surface). CORS-safe.
 */
export const supplyChainProvider: Provider = {
  id: "Supply Chain",
  browserSafe: true,
  async evaluate(ctx): Promise<ProviderResult> {
    const url = `https://www.npmjs.com/package/${ctx.name}/v/${ctx.version}`;
    const base = { provider: "Supply Chain", url };
    try {
      const doc = await getJson<RegistryDoc>(`${REGISTRY}/${encodeURIComponent(ctx.name)}`, {
        fetch: ctx.fetch,
      });
      const v = doc.versions?.[ctx.version];
      if (!v) {
        return { ...base, ok: false, level: "unknown", summary: "Version not found on the registry", findings: [] };
      }

      const findings: ProviderFinding[] = [];

      const deprecated = typeof v.deprecated === "string" ? v.deprecated : undefined;
      if (deprecated) {
        findings.push({ label: "Deprecated", value: deprecated.slice(0, 80) || "yes", level: "high" });
      }

      const hooks = INSTALL_HOOKS.filter((h) => v.scripts?.[h]);
      findings.push({
        label: "Install scripts",
        value: hooks.length ? hooks.join(", ") : "none",
        level: hooks.length ? "medium" : "low",
      });

      const hasProvenance = Boolean(v.dist?.attestations?.provenance);
      findings.push({
        label: "Build provenance",
        value: hasProvenance ? "yes" : "no",
        level: hasProvenance ? "low" : undefined,
      });

      const maintainers = doc.maintainers?.length ?? 0;
      findings.push({
        label: "Maintainers",
        value: String(maintainers),
        level: maintainers === 1 ? "medium" : "low",
      });

      // Only a deprecation raises the overall level; install scripts and a lone
      // maintainer are common enough that they're surfaced as cautions, not alarms.
      const level: RiskLevel = deprecated ? "high" : hooks.length ? "medium" : "low";
      const summary = deprecated
        ? "Deprecated — avoid"
        : [
            hooks.length ? "runs install scripts" : "no install scripts",
            hasProvenance ? "has provenance" : "no provenance",
            `${maintainers} maintainer(s)`,
          ].join(", ");

      return { ...base, ok: true, level, summary, findings };
    } catch (err) {
      return {
        ...base,
        ok: false,
        level: "unknown",
        summary: "Supply-chain lookup failed",
        findings: [],
        error: err instanceof Error ? err.message : String(err),
      };
    }
  },
};
