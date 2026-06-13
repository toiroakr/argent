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
}

export interface PackageRef {
  name: string;
  /** Resolved version actually evaluated. */
  version: string;
  /** Source repository in `host/org/repo` form when known. */
  repoUrl?: string;
}

export interface RiskReport {
  package: PackageRef;
  results: ProviderResult[];
  /** Worst-case level across all providers that ran successfully. */
  overall: RiskLevel;
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
  /** Whether the run is happening in a browser (disables CORS-unsafe calls). */
  browser?: boolean;
}

export interface Provider {
  id: string;
  /** Whether this provider can run inside a browser (CORS-safe, no secrets). */
  browserSafe: boolean;
  evaluate(ctx: EvalContext): Promise<ProviderResult>;
}
