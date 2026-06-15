import { getJson } from "../http.js";
import type { Provider, ProviderFinding, ProviderResult, RiskLevel } from "../types.js";

// ecosyste.ms aggregates dependents + downloads for free (no auth). npm itself
// has no clean dependents API and its website is bot-walled; ecosyste.ms isn't
// CORS-enabled, so this is CLI-only.
const ECOSYSTE = "https://packages.ecosyste.ms/api/v1/registries/npmjs.org/packages";

interface EcosystePackage {
  downloads?: number;
  downloads_period?: string;
  dependent_packages_count?: number;
  dependent_repos_count?: number;
}

function human(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(0)}k`;
  return String(n);
}

/**
 * How widely the package is used (downloads + how many packages/repos depend on
 * it). Two-sided, so it's advisory: heavy use means more eyes — problems tend to
 * be spotted and fixed sooner — but also makes it a more attractive target.
 */
export const popularityProvider: Provider = {
  id: "Popularity",
  browserSafe: false,
  async evaluate(ctx): Promise<ProviderResult> {
    const url = `https://www.npmjs.com/package/${ctx.name}`;
    const base = { provider: "Popularity", advisory: true };
    try {
      const data = await getJson<EcosystePackage>(`${ECOSYSTE}/${encodeURIComponent(ctx.name)}`, {
        fetch: ctx.fetch,
      });
      const downloads = data.downloads ?? 0;
      const depPkgs = data.dependent_packages_count ?? 0;
      const depRepos = data.dependent_repos_count ?? 0;

      const findings: ProviderFinding[] = [
        { label: `Downloads (${data.downloads_period ?? "recent"})`, value: human(downloads) },
        { label: "Dependent packages", value: human(depPkgs) },
        { label: "Dependent repositories", value: human(depRepos) },
      ];

      // More users → more eyes → earlier detection of problems.
      const widely = depPkgs >= 20 || downloads >= 100_000;
      const obscure = depPkgs < 2 && downloads < 1_000;
      const level: RiskLevel = widely ? "low" : obscure ? "medium" : "low";
      const summary = widely
        ? `Widely used (${human(depPkgs)} dependent packages) — many eyes, but a bigger target`
        : obscure
          ? "Rarely used — fewer eyes on it"
          : `Used by ${human(depPkgs)} packages`;

      return { ...base, ok: true, level, summary, findings, url };
    } catch (err) {
      return {
        ...base,
        ok: false,
        level: "unknown",
        summary: "Popularity lookup failed",
        findings: [],
        url,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  },
};
