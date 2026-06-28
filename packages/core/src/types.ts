/**
 * Normalized risk level used across every provider so reports stay comparable
 * regardless of how each upstream service scores things.
 */
export type RiskLevel = "low" | "medium" | "high" | "critical" | "unknown";

/** A single human-readable data point surfaced by a provider. */
export interface ProviderFinding {
  label: string;
  value: string;
  /** Optional per-finding severity, used to highlight individual rows. */
  level?: RiskLevel;
}

/** Result of evaluating one package against a single provider. */
export interface ProviderResult {
  /** Stable provider id, e.g. "deps.dev". */
  provider: string;
  /** Whether the lookup completed without an error. */
  ok: boolean;
  /** Overall risk level derived from this provider. */
  level: RiskLevel;
  /**
   * Normalized 0-100 score where higher means safer/healthier.
   * Undefined when the provider does not expose a comparable score.
   */
  score?: number;
  /** Short one-line summary for terminal/UI display. */
  summary: string;
  /** Detailed rows backing the summary. */
  findings: ProviderFinding[];
  /** Human-facing URL for drilling into the raw data. */
  url?: string;
  /** Populated when ok === false. */
  error?: string;
  /**
   * Set when a provider could not run in the current environment
   * (e.g. requires an API key, or is blocked by CORS in the browser).
   */
  skipped?: boolean;
  /**
   * Marks a result as a separate decision-aid axis (e.g. build-vs-buy) rather
   * than a security signal. Advisory results are shown in the report but are
   * NOT folded into the package's security `overall` level.
   */
  advisory?: boolean;
}

export interface PackageRef {
  name: string;
  /** Resolved version actually evaluated. */
  version: string;
  /** Source repository in `host/org/repo` form when known. */
  repoUrl?: string;
}

/**
 * How much of the security signal actually came back. The `overall` level is a
 * worst-case across the sources that ran — but it says nothing about how many
 * DIDN'T. A package whose security sources mostly errored or were skipped can
 * look as clean as a fully-vetted one; coverage makes that gap explicit so a
 * thin assessment isn't mistaken for a reassuring one.
 */
export interface Coverage {
  /** Security (non-advisory) providers that produced a real signal. */
  evaluated: number;
  /** Total security (non-advisory) providers attempted. */
  total: number;
  /** Security providers that contributed nothing, with why. */
  missing: { provider: string; reason: "skipped" | "error" | "unknown" }[];
}

export interface RiskReport {
  package: PackageRef;
  results: ProviderResult[];
  /** Worst-case level across all providers that ran successfully. */
  overall: RiskLevel;
  /** Security-signal coverage behind `overall` (see {@link Coverage}). */
  coverage: Coverage;
  /** ISO timestamp. */
  generatedAt: string;
}

/** Shared context handed to every provider after package resolution. */
export interface EvalContext {
  name: string;
  version: string;
  /** `host/org/repo`, e.g. "github.com/expressjs/express". */
  repoUrl?: string;
  fetch: typeof fetch;
  /** Provider-specific configuration. */
  config: EvalConfig;
}

export interface EvalConfig {
  /** socket.dev API token; without it the socket provider is skipped. */
  socketApiKey?: string;
  /** GitHub token; raises the API rate limit for the GitHub-based providers. */
  githubToken?: string;
  /** Max workflow files the GitHub Actions provider lints (default 40). */
  maxWorkflows?: number;
  /** Whether the run is happening in a browser (disables CORS-unsafe calls). */
  browser?: boolean;
}

export interface Provider {
  id: string;
  /** Whether this provider can run inside a browser (CORS-safe, no secrets). */
  browserSafe: boolean;
  evaluate(ctx: EvalContext): Promise<ProviderResult>;
}
