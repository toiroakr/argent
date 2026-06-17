import { execFileSync } from "node:child_process";
import { parseArgs } from "node:util";
import {
  auditCommons,
  auditDependencies,
  auditEntries,
  availableProviders,
  type CommonsManifest,
  evaluatePackage,
  type RiskLevel,
} from "@argent/core";
import pc from "picocolors";
import { findManifest, findWorkspaceManifests, loadManifest } from "./manifest.js";
import { renderAudit, renderCommons, renderError, renderReport } from "./render.js";
import { parseSpec } from "./spec.js";

const HELP = `${pc.bold("argent")} — assess the risk of npm packages before you install them

${pc.bold("Usage:")}
  argent <package[@version]> [more packages...] [options]
  argent audit [package[@version]] [options]
  argent commons [package...] [options]

${pc.bold("Examples:")}
  argent express
  argent left-pad@1.3.0 lodash
  argent @sindresorhus/is --json
  argent chalk --fail-on high      ${pc.dim("# non-zero exit if risk >= high (for CI)")}
  argent audit                     ${pc.dim("# audit the nearest package.json")}
  argent audit express             ${pc.dim("# rank which dependencies to drop")}
  argent audit webpack --top 30 --direct
  argent commons                   ${pc.dim("# deps shared across your workspace packages")}
  argent commons express koa       ${pc.dim("# deps common to several published packages")}

${pc.bold("Options:")}
  --json             Output the raw report as JSON
  --fail-on <level>  Exit non-zero when overall risk >= level
                     (low | medium | high | critical)
  --socket-key <k>   socket.dev API token (or set SOCKET_API_KEY)
  --no-color         Disable colored output
  -h, --help         Show this help

${pc.bold("audit options:")}
  (with no package, audits the nearest package.json)
  --top <n>          Show only the top N drop candidates (default 25)
  --direct           Audit only direct dependencies (published-package mode)
  --prod             Skip devDependencies (package.json mode)
  --max <n>          Cap dependencies evaluated (default 250)

${pc.bold("commons:")} rank dependencies shared across multiple packages you manage
  (a common, mundane dep is worth reimplementing once and dropping everywhere).
  With no args, discovers your workspace packages; or pass package names.
  --top <n>          Show only the top N (default 25)
  --prod             Ignore devDependencies

${pc.bold("Sources:")} deps.dev, OpenSSF Scorecard, Supply Chain, socket.dev,
Snyk Advisor, GitHub Actions (karinto), Community, Popularity, License,
Build-vs-Buy.
${pc.dim("GitHub auth: uses GITHUB_TOKEN, else the logged-in gh CLI (gh auth token).")}
`;

/**
 * Resolves a GitHub token for the GitHub-based providers: an explicit env var
 * wins, otherwise fall back to the locally authenticated `gh` CLI so most
 * developers get authenticated (rate-limit-relieved, private-repo) reads for
 * free without configuring anything.
 */
function resolveGithubToken(): { token?: string; viaGh?: boolean } {
  const fromEnv = process.env.GITHUB_TOKEN ?? process.env.GH_TOKEN;
  if (fromEnv) return { token: fromEnv };
  try {
    const token = execFileSync("gh", ["auth", "token"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 5_000,
    }).trim();
    return token ? { token, viaGh: true } : {};
  } catch {
    return {};
  }
}

const SEVERITY: RiskLevel[] = ["low", "medium", "high", "critical"];

function meetsThreshold(level: RiskLevel, threshold: RiskLevel): boolean {
  const a = SEVERITY.indexOf(level);
  const b = SEVERITY.indexOf(threshold);
  return a >= 0 && b >= 0 && a >= b;
}

interface AuditFlags {
  json?: boolean;
  top?: string;
  direct?: boolean;
  max?: string;
  prod?: boolean;
}

async function runAudit(args: string[], values: AuditFlags): Promise<number> {
  const top = values.top ? Number(values.top) : 25;
  const maxDeps = values.max ? Number(values.max) : undefined;
  const target = args[0];

  try {
    // No package given: audit the dependencies in the nearest package.json.
    if (!target) {
      const manifestPath = findManifest(process.cwd());
      if (!manifestPath) {
        process.stderr.write(
          renderError("argent", "no package.json found in this directory or any parent") +
            "\n",
        );
        return 2;
      }
      const manifest = loadManifest(manifestPath, !values.prod);
      if (!values.json) {
        process.stderr.write(
          pc.dim(
            `Auditing ${manifest.entries.length} dependencies from ${manifestPath}…`,
          ) + "\n",
        );
      }
      const report = await auditEntries(
        { name: manifest.name, version: manifest.version },
        manifest.entries,
        { maxDeps },
      );
      writeAudit(report, top, values.json);
      return 0;
    }

    const { name, version } = parseSpec(target);
    if (!values.json) {
      process.stderr.write(
        pc.dim(`Auditing dependencies of ${name}${version ? "@" + version : ""}…`) + "\n",
      );
    }
    const report = await auditDependencies(name, {
      version,
      directOnly: values.direct,
      maxDeps,
    });
    writeAudit(report, top, values.json);
    return 0;
  } catch (err) {
    process.stderr.write(
      renderError(target ?? "audit", err instanceof Error ? err.message : String(err)) +
        "\n",
    );
    return 1;
  }
}

function writeAudit(
  report: Parameters<typeof renderAudit>[0],
  top: number,
  json: boolean | undefined,
): void {
  if (json) process.stdout.write(JSON.stringify(report, null, 2) + "\n");
  else process.stdout.write(renderAudit(report, top));
}

/** Builds a manifest from a published package's declared direct dependencies. */
async function publishedManifest(
  name: string,
  includeDev: boolean,
): Promise<CommonsManifest | null> {
  try {
    const doc = (await (
      await fetch(`https://registry.npmjs.org/${encodeURIComponent(name)}`)
    ).json()) as {
      "dist-tags"?: { latest?: string };
      versions?: Record<
        string,
        { dependencies?: Record<string, string>; devDependencies?: Record<string, string> }
      >;
    };
    const latest = doc["dist-tags"]?.latest;
    const v = latest ? doc.versions?.[latest] : undefined;
    if (!v) return null;
    const entries = [
      ...Object.keys(v.dependencies ?? {}).map((n) => ({ name: n, dev: false })),
      ...(includeDev
        ? Object.keys(v.devDependencies ?? {}).map((n) => ({ name: n, dev: true }))
        : []),
    ];
    return { name, entries };
  } catch {
    return null;
  }
}

async function runCommons(args: string[], values: AuditFlags): Promise<number> {
  const top = values.top ? Number(values.top) : 25;
  const includeDev = !values.prod;

  let manifests: CommonsManifest[];
  let label: string;
  try {
    if (args.length > 0) {
      // Common deps across the given published packages.
      const built = await Promise.all(args.map((a) => publishedManifest(parseSpec(a).name, includeDev)));
      manifests = built.filter((m): m is CommonsManifest => m !== null);
      label = `${manifests.length} packages`;
    } else {
      // Common deps across your local workspace packages.
      const ws = findWorkspaceManifests(process.cwd(), includeDev);
      if (!ws) {
        process.stderr.write(
          renderError(
            "argent",
            "no workspace found (pnpm-workspace.yaml or package.json \"workspaces\"). Pass package names to compare instead: argent commons <a> <b> …",
          ) + "\n",
        );
        return 2;
      }
      manifests = ws.manifests;
      label = `${manifests.length} workspace packages`;
    }

    if (manifests.length < 2) {
      process.stderr.write(
        renderError("argent", "need at least 2 packages to find common dependencies") + "\n",
      );
      return 2;
    }

    if (!values.json) process.stderr.write(pc.dim(`Analyzing ${label}…`) + "\n");
    const report = await auditCommons(manifests);
    if (values.json) process.stdout.write(JSON.stringify(report, null, 2) + "\n");
    else process.stdout.write(renderCommons(report, top));
    return 0;
  } catch (err) {
    process.stderr.write(
      renderError("commons", err instanceof Error ? err.message : String(err)) + "\n",
    );
    return 1;
  }
}

async function main(): Promise<number> {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      json: { type: "boolean", default: false },
      "fail-on": { type: "string" },
      "socket-key": { type: "string" },
      color: { type: "boolean" },
      top: { type: "string" },
      direct: { type: "boolean", default: false },
      max: { type: "string" },
      prod: { type: "boolean", default: false },
      help: { type: "boolean", short: "h", default: false },
    },
  });

  if (values.help || positionals.length === 0) {
    process.stdout.write(HELP);
    return positionals.length === 0 && !values.help ? 1 : 0;
  }

  if (positionals[0] === "audit") {
    return runAudit(positionals.slice(1), values);
  }
  if (positionals[0] === "commons") {
    return runCommons(positionals.slice(1), values);
  }

  const failOn = values["fail-on"] as RiskLevel | undefined;
  if (failOn && !SEVERITY.includes(failOn)) {
    process.stderr.write(
      renderError("argent", `invalid --fail-on value: ${failOn}`) + "\n",
    );
    return 2;
  }

  const socketApiKey = values["socket-key"] ?? process.env.SOCKET_API_KEY;
  const github = resolveGithubToken();

  if (!values.json) {
    process.stderr.write(
      pc.dim(`Sources: ${availableProviders(false).join(", ")}`) +
        (socketApiKey ? "" : pc.dim("  (socket.dev disabled — no API key)")) +
        (github.token
          ? github.viaGh
            ? pc.dim("  (GitHub via gh)")
            : ""
          : pc.dim("  (GitHub unauthenticated — set GITHUB_TOKEN or run gh auth login)")) +
        "\n",
    );
  }
  const githubToken = github.token;

  const reports = await Promise.all(
    positionals.map(async (spec) => {
      const { name, version } = parseSpec(spec);
      try {
        return await evaluatePackage(name, { version, socketApiKey, githubToken });
      } catch (err) {
        return {
          error: err instanceof Error ? err.message : String(err),
          name,
        };
      }
    }),
  );

  if (values.json) {
    process.stdout.write(JSON.stringify(reports, null, 2) + "\n");
  } else {
    for (const r of reports) {
      if ("error" in r) process.stdout.write(renderError(r.name, r.error) + "\n");
      else process.stdout.write(renderReport(r));
    }
  }

  if (failOn) {
    const tripped = reports.some(
      (r) => !("error" in r) && meetsThreshold(r.overall, failOn),
    );
    if (tripped) return 1;
  }
  const anyError = reports.some((r) => "error" in r);
  return anyError ? 1 : 0;
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    process.stderr.write(`${pc.red("argent crashed:")} ${err?.message ?? err}\n`);
    process.exit(2);
  });
