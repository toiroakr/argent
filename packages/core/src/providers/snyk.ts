import { getText } from "../http.js";
import { levelFromScore } from "../risk.js";
import type { Provider, ProviderResult } from "../types.js";

/**
 * Snyk Advisor has no public API, so this scrapes the package's Advisor page.
 * Scraping is best-effort and brittle by nature: when the markup changes we
 * fall back to "unknown" rather than guessing. CORS blocks it in the browser,
 * where the UI links out instead.
 */
export const snykProvider: Provider = {
  id: "Snyk Advisor",
  browserSafe: false,
  async evaluate(ctx): Promise<ProviderResult> {
    const url = `https://snyk.io/advisor/npm-package/${ctx.name}`;
    const base = { provider: "Snyk Advisor", url };

    try {
      const html = await getText(url, {
        fetch: ctx.fetch,
        headers: { "user-agent": "argent/0.1 (+https://github.com/toiroakr/argent)" },
      });

      const score = extractScore(html);

      if (score === undefined) {
        return {
          ...base,
          ok: true,
          level: "unknown",
          summary: "Could not parse Snyk health score (see the Advisor page)",
          findings: [],
        };
      }

      return {
        ...base,
        ok: true,
        score,
        level: levelFromScore(score),
        summary: `Snyk health score ${score}/100`,
        findings: [],
      };
    } catch (err) {
      return {
        ...base,
        ok: false,
        level: "unknown",
        summary: "Snyk Advisor lookup failed",
        findings: [],
        error: err instanceof Error ? err.message : String(err),
      };
    }
  },
};

function extractScore(html: string): number | undefined {
  // Preferred: structured Next.js data blob.
  const next = html.match(/<script id="__NEXT_DATA__"[^>]*>([\s\S]*?)<\/script>/);
  if (next?.[1]) {
    const m = next[1].match(/"score"\s*:\s*(\d{1,3})/);
    if (m?.[1]) return clamp(Number(m[1]));
  }
  // Fallbacks on rendered markup.
  const byClass = html.match(/class="[^"]*\bnumber\b[^"]*"[^>]*>\s*(\d{1,3})\s*</);
  if (byClass?.[1]) return clamp(Number(byClass[1]));
  const byLabel = html.match(/(\d{1,3})\s*\/\s*100/);
  if (byLabel?.[1]) return clamp(Number(byLabel[1]));
  return undefined;
}

function clamp(n: number): number | undefined {
  return Number.isFinite(n) && n >= 0 && n <= 100 ? n : undefined;
}
