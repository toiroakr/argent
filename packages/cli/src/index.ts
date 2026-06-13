import { parseArgs } from "node:util";
import { availableProviders, evaluatePackage, type RiskLevel } from "@argent/core";
import pc from "picocolors";
import { renderError, renderReport } from "./render.js";
import { parseSpec } from "./spec.js";

const HELP = `${pc.bold("argent")} — assess the risk of npm packages before you install them

${pc.bold("Usage:")}
  argent <package[@version]> [more packages...] [options]

${pc.bold("Examples:")}
  argent express
  argent left-pad@1.3.0 lodash
  argent @sindresorhus/is --json
  argent chalk --fail-on high      ${pc.dim("# non-zero exit if risk >= high (for CI)")}

${pc.bold("Options:")}
  --json             Output the raw report as JSON
  --fail-on <level>  Exit non-zero when overall risk >= level
                     (low | medium | high | critical)
  --socket-key <k>   socket.dev API token (or set SOCKET_API_KEY)
  --no-color         Disable colored output
  -h, --help         Show this help

${pc.bold("Sources:")} deps.dev, OpenSSF Scorecard, socket.dev, Snyk Advisor.
`;

const SEVERITY: RiskLevel[] = ["low", "medium", "high", "critical"];

function meetsThreshold(level: RiskLevel, threshold: RiskLevel): boolean {
  const a = SEVERITY.indexOf(level);
  const b = SEVERITY.indexOf(threshold);
  return a >= 0 && b >= 0 && a >= b;
}

async function main(): Promise<number> {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      json: { type: "boolean", default: false },
      "fail-on": { type: "string" },
      "socket-key": { type: "string" },
      color: { type: "boolean" },
      help: { type: "boolean", short: "h", default: false },
    },
  });

  if (values.help || positionals.length === 0) {
    process.stdout.write(HELP);
    return positionals.length === 0 && !values.help ? 1 : 0;
  }

  const failOn = values["fail-on"] as RiskLevel | undefined;
  if (failOn && !SEVERITY.includes(failOn)) {
    process.stderr.write(
      renderError("argent", `invalid --fail-on value: ${failOn}`) + "\n",
    );
    return 2;
  }

  const socketApiKey = values["socket-key"] ?? process.env.SOCKET_API_KEY;

  if (!values.json) {
    process.stderr.write(
      pc.dim(`Sources: ${availableProviders(false).join(", ")}`) +
        (socketApiKey ? "" : pc.dim("  (socket.dev disabled — no API key)")) +
        "\n",
    );
  }

  const reports = await Promise.all(
    positionals.map(async (spec) => {
      const { name, version } = parseSpec(spec);
      try {
        return await evaluatePackage(name, { version, socketApiKey });
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
