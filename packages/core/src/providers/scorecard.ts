import { getJson, HttpError } from "../http.js";
import { levelFromScore } from "../risk.js";
import type { Provider, ProviderFinding, ProviderResult } from "../types.js";

const BASE = "https://api.securityscorecards.dev";

interface ScorecardCheck {
  name: string;
  score: number; // 0-10, -1 when inconclusive
  reason?: string;
}

interface ScorecardResponse {
  score?: number; // 0-10
  checks?: ScorecardCheck[];
  date?: string;
}

/** Checks whose failure is most relevant to supply-chain risk. */
const HIGHLIGHT = new Set([
  "Maintained",
  "Vulnerabilities",
  "Dangerous-Workflow",
  "Token-Permissions",
  // The security counterpart of accepting outside contributions: whether they
  // get reviewed / land on protected branches (guards against malicious PRs).
  "Code-Review",
  "Branch-Protection",
  "Signed-Releases",
]);

/**
 * OpenSSF Scorecard runs heuristic security checks on the source repository.
 * CORS-safe and unauthenticated, so it works in the browser too.
 */
export const scorecardProvider: Provider = {
  id: "OpenSSF Scorecard",
  browserSafe: true,
  async evaluate(ctx): Promise<ProviderResult> {
    const base: Omit<ProviderResult, "level" | "summary" | "findings" | "ok"> = {
      provider: "OpenSSF Scorecard",
    };

    if (!ctx.repoUrl) {
      return {
        ...base,
        ok: false,
        skipped: true,
        level: "unknown",
        summary: "No source repository known for this package",
        findings: [],
      };
    }

    const url = `https://securityscorecards.dev/viewer/?uri=${ctx.repoUrl}`;
    try {
      const data = await getJson<ScorecardResponse>(
        `${BASE}/projects/${ctx.repoUrl}`,
        { fetch: ctx.fetch },
      );
      const score10 = data.score ?? 0;
      const score100 = Math.round(score10 * 10);
      const findings: ProviderFinding[] = (data.checks ?? [])
        .filter((c) => HIGHLIGHT.has(c.name))
        .map((c) => ({
          label: c.name,
          value: c.score < 0 ? "n/a" : `${c.score}/10`,
          level:
            c.score < 0 ? "unknown" : levelFromScore(c.score * 10),
        }));

      return {
        ...base,
        ok: true,
        score: score100,
        level: levelFromScore(score100),
        summary: `Scorecard ${score10.toFixed(1)}/10`,
        findings,
        url,
      };
    } catch (err) {
      const notFound = err instanceof HttpError && err.status === 404;
      return {
        ...base,
        ok: false,
        skipped: notFound,
        level: "unknown",
        summary: notFound
          ? "No Scorecard data for this repository"
          : "Scorecard lookup failed",
        findings: [],
        url,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  },
};
