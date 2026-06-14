import type { ProviderResult, RiskLevel, RiskReport } from "@argent/core";
import pc from "picocolors";

const LEVEL_LABEL: Record<RiskLevel, string> = {
  low: "LOW",
  medium: "MEDIUM",
  high: "HIGH",
  critical: "CRITICAL",
  unknown: "UNKNOWN",
};

function paintLevel(level: RiskLevel): string {
  const label = LEVEL_LABEL[level];
  switch (level) {
    case "low":
      return pc.green(label);
    case "medium":
      return pc.yellow(label);
    case "high":
      return pc.red(label);
    case "critical":
      return pc.bgRed(pc.white(` ${label} `));
    default:
      return pc.dim(label);
  }
}

/**
 * Advisory (build-vs-buy) results are an adoption axis, not a security
 * severity, so they get a neutral verdict tag instead of risk colors.
 */
const ADVISORY_TAG: Record<RiskLevel, string> = {
  high: pc.cyan("REIMPLEMENT?"),
  medium: pc.yellow("CONSIDER"),
  low: pc.green("KEEP"),
  critical: pc.green("KEEP"),
  unknown: pc.dim("N/A"),
};

function statusIcon(r: ProviderResult): string {
  if (r.advisory) return r.ok ? "💡" : pc.red("✗");
  if (r.skipped) return pc.dim("○");
  if (!r.ok) return pc.red("✗");
  switch (r.level) {
    case "low":
      return pc.green("✓");
    case "medium":
      return pc.yellow("▲");
    case "high":
    case "critical":
      return pc.red("✗");
    default:
      return pc.dim("○");
  }
}

export function renderReport(report: RiskReport): string {
  const { package: pkg } = report;
  const lines: string[] = [];

  lines.push("");
  lines.push(
    `${pc.bold(pkg.name)}${pc.dim("@")}${pkg.version}  ${paintLevel(report.overall)}`,
  );
  if (pkg.repoUrl) lines.push(pc.dim(`  ${pkg.repoUrl}`));
  lines.push("");

  for (const r of report.results) {
    const tag =
      r.advisory && r.ok
        ? ` ${ADVISORY_TAG[r.level]}`
        : r.score !== undefined
          ? pc.dim(` [${r.score}/100]`)
          : "";
    lines.push(`  ${statusIcon(r)} ${pc.bold(r.provider)}${tag}  ${r.summary}`);
    if (r.error) lines.push(pc.dim(`      ${r.error}`));
    for (const f of r.findings) {
      const lvl = f.level && f.level !== "unknown" ? ` ${paintLevel(f.level)}` : "";
      lines.push(pc.dim(`      • ${f.label}: ${f.value}`) + lvl);
    }
    if (r.url) lines.push(pc.dim(pc.underline(`      ${r.url}`)));
    lines.push("");
  }

  return lines.join("\n");
}

export function renderError(name: string, message: string): string {
  return `${pc.red("✗")} ${pc.bold(name)}  ${message}`;
}
