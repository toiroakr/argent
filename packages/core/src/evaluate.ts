import { evaluateDepsDev } from "./providers/depsdev.js";
import { reimplementabilityProvider } from "./providers/reimplementability.js";
import { scorecardProvider } from "./providers/scorecard.js";
import { snykProvider } from "./providers/snyk.js";
import { socketProvider } from "./providers/socket.js";
import { aggregate } from "./risk.js";
import type {
  EvalConfig,
  EvalContext,
  Provider,
  ProviderResult,
  RiskReport,
} from "./types.js";

/** Providers that run after deps.dev resolves the version + repo. */
const SECONDARY: Provider[] = [
  scorecardProvider,
  socketProvider,
  snykProvider,
  reimplementabilityProvider,
];

export interface EvaluateOptions extends EvalConfig {
  /** Specific version to evaluate; defaults to the package's default version. */
  version?: string;
  /** Override fetch (defaults to global fetch). */
  fetch?: typeof fetch;
}

/** Returns the set of providers that can run in the given environment. */
export function availableProviders(browser: boolean): string[] {
  const ids = ["deps.dev", ...SECONDARY.map((p) => p.id)];
  if (!browser) return ids;
  return ids.filter(
    (id) => id === "deps.dev" || SECONDARY.find((p) => p.id === id)?.browserSafe,
  );
}

/**
 * Evaluates an npm package across every configured provider and returns a
 * single normalized report. deps.dev runs first to resolve the version and
 * source repository, then the remaining providers run in parallel.
 */
export async function evaluatePackage(
  name: string,
  options: EvaluateOptions = {},
): Promise<RiskReport> {
  const fetchImpl = options.fetch ?? globalThis.fetch;
  if (!fetchImpl) throw new Error("No fetch implementation available");

  const config: EvalConfig = {
    socketApiKey: options.socketApiKey,
    browser: options.browser ?? false,
  };

  const resolved = await evaluateDepsDev(name, options.version, {
    fetch: fetchImpl,
  });

  const ctx: EvalContext = {
    name,
    version: resolved.version,
    repoUrl: resolved.repoUrl,
    fetch: fetchImpl,
    config,
  };

  const secondary = await Promise.all(
    SECONDARY.map(async (p): Promise<ProviderResult> => {
      if (config.browser && !p.browserSafe) {
        return {
          provider: p.id,
          ok: false,
          skipped: true,
          level: "unknown",
          summary: "Not available in the browser (requires the CLI)",
          findings: [],
        };
      }
      return p.evaluate(ctx);
    }),
  );

  const results = [resolved.result, ...secondary];
  // Advisory axes (e.g. build-vs-buy) are informational and must not raise the
  // security overall level.
  const overall = aggregate(
    results.filter((r) => r.ok && !r.advisory).map((r) => r.level),
  );

  return {
    package: { name, version: resolved.version, repoUrl: resolved.repoUrl },
    results,
    overall,
    generatedAt: new Date().toISOString(),
  };
}
