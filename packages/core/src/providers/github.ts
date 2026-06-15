import { getJson, getText, HttpError, postText } from "../http.js";
import type { Provider, ProviderFinding, ProviderResult, RiskLevel } from "../types.js";

const GH_API = "https://api.github.com";
const KARINTO = "https://karinto.toiroakr.workers.dev";

/** Parses a deps.dev repo id into owner/repo, GitHub only. */
function parseGithub(repoUrl: string | undefined): { owner: string; repo: string } | undefined {
  if (!repoUrl) return undefined;
  const m = repoUrl.match(/^github\.com\/([^/]+)\/([^/]+)/);
  return m ? { owner: m[1]!, repo: m[2]!.replace(/\.git$/, "") } : undefined;
}

function ghHeaders(token: string | undefined): Record<string, string> {
  const h: Record<string, string> = {
    accept: "application/vnd.github+json",
    "user-agent": "argent",
  };
  if (token) h.authorization = `Bearer ${token}`;
  return h;
}

function rateLimited(err: unknown): boolean {
  return err instanceof HttpError && (err.status === 403 || err.status === 429);
}

// --------------------------------------------------------------- GitHub Actions

interface KarintoResult {
  result?: {
    diagnostics?: { rule: string; severity: string; message: string }[];
  };
}

interface WorkflowFile {
  name: string;
  download_url: string | null;
}

/**
 * Lints the repository's GitHub Actions workflows with karinto (72 rules:
 * excessive permissions, dangerous triggers, unpinned actions, template
 * injection, …). A security axis: bad CI hygiene is a real supply-chain risk.
 * CLI-only — GitHub's API is rate-limited without a token.
 */
export const githubActionsProvider: Provider = {
  id: "GitHub Actions",
  browserSafe: false,
  async evaluate(ctx): Promise<ProviderResult> {
    const gh = parseGithub(ctx.repoUrl);
    const base = { provider: "GitHub Actions" };
    if (!gh) {
      return { ...base, ok: false, skipped: true, level: "unknown", summary: "No GitHub repository known", findings: [] };
    }
    const url = `https://github.com/${gh.owner}/${gh.repo}/actions`;
    const headers = ghHeaders(ctx.config.githubToken);

    try {
      let files: WorkflowFile[];
      try {
        files = await getJson<WorkflowFile[]>(
          `${GH_API}/repos/${gh.owner}/${gh.repo}/contents/.github/workflows`,
          { fetch: ctx.fetch, headers },
        );
      } catch (err) {
        if (err instanceof HttpError && err.status === 404) {
          return { ...base, ok: true, level: "low", summary: "No GitHub Actions workflows", findings: [], url };
        }
        throw err;
      }

      const ymls = files
        .filter((f) => /\.ya?ml$/.test(f.name) && f.download_url)
        .slice(0, 12);
      if (ymls.length === 0) {
        return { ...base, ok: true, level: "low", summary: "No workflow files", findings: [], url };
      }

      const counts: Record<string, number> = { error: 0, warning: 0, info: 0 };
      const ruleCounts = new Map<string, { severity: string; n: number }>();
      for (const f of ymls) {
        const yaml = await getText(f.download_url!, { fetch: ctx.fetch });
        const res = await postText(KARINTO, yaml, {
          fetch: ctx.fetch,
          headers: { "content-type": "text/plain" },
        }).then((t) => JSON.parse(t) as KarintoResult);
        for (const d of res.result?.diagnostics ?? []) {
          counts[d.severity] = (counts[d.severity] ?? 0) + 1;
          const cur = ruleCounts.get(d.rule) ?? { severity: d.severity, n: 0 };
          cur.n++;
          ruleCounts.set(d.rule, cur);
        }
      }

      // CI hygiene is an indirect supply-chain signal, so cap its weight: a lint
      // error maps to medium (not high) and won't alone make a package "high".
      const level: RiskLevel = counts.error! > 0 ? "medium" : "low";
      const findings: ProviderFinding[] = [...ruleCounts.entries()]
        .sort((a, b) => severityRank(b[1].severity) - severityRank(a[1].severity) || b[1].n - a[1].n)
        .slice(0, 5)
        .map(([rule, v]) => ({
          label: rule,
          value: `${v.n}× ${v.severity}`,
          level: karintoLevel(v.severity),
        }));

      const parts = [
        counts.error ? `${counts.error} error` : "",
        counts.warning ? `${counts.warning} warning` : "",
        counts.info ? `${counts.info} info` : "",
      ].filter(Boolean);
      return {
        ...base,
        ok: true,
        level,
        summary: `${ymls.length} workflow(s): ${parts.length ? parts.join(", ") : "clean"}`,
        findings,
        url,
      };
    } catch (err) {
      return {
        ...base,
        ok: false,
        skipped: rateLimited(err),
        level: "unknown",
        summary: rateLimited(err)
          ? "GitHub API rate-limited — set GITHUB_TOKEN"
          : "GitHub Actions lint failed",
        findings: [],
        url,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  },
};

function severityRank(s: string): number {
  return s === "error" ? 3 : s === "warning" ? 2 : 1;
}
// One step below karinto's severity: CI findings are indirect for a consumer.
function karintoLevel(s: string): RiskLevel {
  return s === "error" ? "medium" : "low";
}

// ------------------------------------------------------------------- Community

interface RepoMeta {
  archived?: boolean;
  disabled?: boolean;
  has_issues?: boolean;
  open_issues_count?: number;
  pushed_at?: string;
  private?: boolean;
  visibility?: string;
}
interface CommunityProfile {
  health_percentage?: number;
  files?: Record<string, unknown>;
}
interface PullRequest {
  merged_at: string | null;
  author_association: string;
}
interface Issue {
  created_at: string;
  closed_at: string | null;
  /** Present when the "issue" is actually a pull request — excluded. */
  pull_request?: unknown;
}

/** Median days-to-close over recently closed real issues (PRs excluded). */
function medianCloseDays(issues: Issue[]): number | undefined {
  const days = issues
    .filter((i) => !i.pull_request && i.closed_at)
    .map((i) => (Date.parse(i.closed_at!) - Date.parse(i.created_at)) / 86_400_000)
    .filter((d) => Number.isFinite(d) && d >= 0)
    .sort((a, b) => a - b);
  if (days.length === 0) return undefined;
  const mid = Math.floor(days.length / 2);
  const median = days.length % 2 ? days[mid]! : (days[mid - 1]! + days[mid]!) / 2;
  return Math.round(median);
}

const EXTERNAL = new Set(["CONTRIBUTOR", "FIRST_TIME_CONTRIBUTOR", "FIRST_TIMER", "NONE", "MANNEQUIN"]);

/**
 * Reports whether the project looks open to outside contributions — useful when
 * deciding whether you could realistically land a fix yourself. Advisory: it's
 * an adoption signal, not a security severity. CLI-only (GitHub API limits).
 */
export const communityProvider: Provider = {
  id: "Community",
  browserSafe: false,
  async evaluate(ctx): Promise<ProviderResult> {
    const gh = parseGithub(ctx.repoUrl);
    const base = { provider: "Community", advisory: true };
    if (!gh) {
      return { ...base, ok: false, skipped: true, level: "unknown", summary: "No GitHub repository known", findings: [] };
    }
    const url = `https://github.com/${gh.owner}/${gh.repo}`;
    const headers = ghHeaders(ctx.config.githubToken);
    const repoBase = `${GH_API}/repos/${gh.owner}/${gh.repo}`;

    try {
      const [repo, profile, pulls, issues] = await Promise.all([
        getJson<RepoMeta>(repoBase, { fetch: ctx.fetch, headers }),
        getJson<CommunityProfile>(`${repoBase}/community/profile`, { fetch: ctx.fetch, headers }).catch(
          () => undefined,
        ),
        getJson<PullRequest[]>(`${repoBase}/pulls?state=closed&per_page=30`, {
          fetch: ctx.fetch,
          headers,
        }).catch(() => [] as PullRequest[]),
        getJson<Issue[]>(`${repoBase}/issues?state=closed&sort=updated&per_page=30`, {
          fetch: ctx.fetch,
          headers,
        }).catch(() => [] as Issue[]),
      ]);

      // A private/internal repo isn't an open-source contribution setting, so the
      // "external PRs" axis doesn't apply; we report it neutrally instead of
      // penalising it. Likewise, absent PRs/issues mean "nothing to assess", not
      // "closed off".
      const isPublic = !repo.private && (repo.visibility ?? "public") === "public";
      const havePulls = pulls.length > 0;
      const externalMerged = pulls.filter(
        (p) => p.merged_at && EXTERNAL.has(p.author_association),
      ).length;
      const hasContributing = Boolean(profile?.files?.["contributing"]);
      const closeDays = medianCloseDays(issues);

      const findings: ProviderFinding[] = [
        {
          label: "Status",
          value: repo.archived ? "archived" : repo.disabled ? "disabled" : "active",
          level: repo.archived || repo.disabled ? "high" : "low",
        },
        { label: "Visibility", value: repo.visibility ?? (repo.private ? "private" : "public") },
        { label: "Issues", value: repo.has_issues ? "enabled" : "disabled" },
        { label: "CONTRIBUTING", value: hasContributing ? "yes" : "no" },
      ];
      // Only meaningful for a public repo that actually has recent PRs to judge.
      if (isPublic && havePulls) {
        findings.push({
          label: "Recent external PRs merged",
          value: String(externalMerged),
          level: externalMerged > 0 ? "low" : "medium",
        });
      }
      if (closeDays !== undefined) {
        findings.push({
          label: "Median issue close time",
          value: `${closeDays}d`,
          level: closeDays <= 14 ? "low" : closeDays <= 90 ? "medium" : "high",
        });
      }

      let level: RiskLevel;
      let summary: string;
      if (repo.archived || repo.disabled) {
        level = "high";
        summary = "Archived/disabled — unlikely to accept contributions";
      } else if (!isPublic) {
        level = "low";
        summary = "Internal/private repository — outside-contribution signals don't apply";
      } else if (externalMerged > 0 || hasContributing) {
        level = "low";
        // Openness helps adoption (you could land a fix) but is also attack
        // surface — the security side is review rigor (see Scorecard Code-Review).
        summary = `Open to contributions (${externalMerged} recent external PR(s) merged) — also widens the attack surface`;
      } else if (!havePulls) {
        level = "low";
        summary = "No recent PR/issue activity to assess outside contribution";
      } else {
        level = "medium";
        summary = "Recent PRs are maintainer-only — limited sign of outside contribution";
      }

      return { ...base, ok: true, level, summary, findings, url };
    } catch (err) {
      return {
        ...base,
        ok: false,
        skipped: rateLimited(err),
        level: "unknown",
        summary: rateLimited(err)
          ? "GitHub API rate-limited — set GITHUB_TOKEN"
          : "Community lookup failed",
        findings: [],
        url,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  },
};
