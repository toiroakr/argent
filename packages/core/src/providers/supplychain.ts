import { getJson } from "../http.js";
import { REGISTRY, type RegistryDoc } from "../npm.js";
import { type RepoTrust, verifyRepo } from "../provenance.js";
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
      // When the package ships provenance, confirm it was actually built from the
      // repo its metadata links to — a mismatch means the linked repo (and the
      // Scorecard/Actions/Community scores derived from it) can't be trusted.
      let trust: RepoTrust = "unverified";
      let attestedRepo: string | undefined;
      if (hasProvenance) {
        const res = await verifyRepo(ctx.name, ctx.version, ctx.repoUrl, ctx.fetch);
        trust = res.trust;
        attestedRepo = res.attestedRepo;
      }
      findings.push({
        label: "Build provenance",
        value: !hasProvenance
          ? "no"
          : trust === "mismatch"
            ? `yes, but attests ${attestedRepo} (≠ linked repo)`
            : trust === "verified"
              ? "yes (repo verified)"
              : "yes",
        level: trust === "mismatch" ? "high" : hasProvenance ? "low" : undefined,
      });

      const maintainers = doc.maintainers?.length ?? 0;
      findings.push({
        label: "Maintainers",
        value: String(maintainers),
        level: maintainers === 1 ? "medium" : "low",
      });

      // A provenance/repo mismatch is a spoofing signal, so it raises the level
      // outright. Otherwise only a deprecation does; install scripts and a lone
      // maintainer are common enough that they're surfaced as cautions, not alarms.
      const level: RiskLevel =
        trust === "mismatch" ? "high" : deprecated ? "high" : hooks.length ? "medium" : "low";
      const summary =
        trust === "mismatch"
          ? `Provenance mismatch — links ${ctx.repoUrl} but was built from ${attestedRepo} (possible repo spoofing)`
          : deprecated
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
