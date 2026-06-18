import type {
  AuditReport,
  CommonsReport,
  DepAudit,
  ProviderResult,
  RiskLevel,
  RiskReport,
} from "@argent/core";
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
    // The REIMPLEMENT?/CONSIDER/KEEP verdict is specific to Build-vs-Buy; other
    // advisory providers (e.g. Community) just show 💡 + their summary.
    const tag =
      r.advisory && r.ok
        ? r.provider === "Build-vs-Buy"
          ? ` ${ADVISORY_TAG[r.level]}`
          : ""
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

function paintDropValue(score: number, text: string): string {
  if (score >= 70) return pc.bold(pc.red(text));
  if (score >= 45) return pc.yellow(text);
  if (score >= 25) return pc.cyan(text);
  return pc.dim(text);
}

const VERDICT_COLOR: Record<DepAudit["verdict"], (s: string) => string> = {
  reimplement: pc.cyan,
  consider: pc.yellow,
  keep: pc.dim,
  unknown: pc.dim,
};

/** Pad a plain cell to width, then apply color (so color codes don't skew it). */
function cell(plain: string, width: number, paint?: (s: string) => string): string {
  const padded = plain.padEnd(width);
  return paint ? paint(padded) : padded;
}

function humanBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes}B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)}KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)}MB`;
}

/** Compact dropScore breakdown: the three weighted factors (each /100). */
function dropBreakdown(d: DepAudit): string {
  const b = d.breakdown;
  if (!b) return d.reasons[0] ?? "";
  if (b.sensitive) return "sensitive — kept low";
  return `own ${b.ownCode} · self ${b.selfContained} · ftpt ${b.footprint}`;
}

/** Renders one ranked table (header + rows + overflow note) for a dep group. */
function auditTable(deps: DepAudit[], top: number): string[] {
  const lines: string[] = [];
  const shown = deps.slice(0, top);
  const rows = shown.map((d) => ({
    d,
    // ⚙ marks a dependency that runs install scripts.
    pkg: `${d.name}@${d.version}${d.direct ? "" : " ·"}${d.installScript ? " ⚙" : ""}`,
    size:
      d.footprintBytes !== undefined
        ? humanBytes(d.footprintBytes) + (d.footprintApprox ? "+" : "")
        : "?",
    risk: d.deprecated
      ? "deprecated"
      : d.advisoryCount === 0
        ? "clean"
        : `${d.severity}(${d.advisoryCount})`,
  }));
  const pkgW = Math.max(7, ...rows.map((r) => r.pkg.length));
  const sizeW = Math.max(6, ...rows.map((r) => r.size.length));
  const riskW = Math.max(4, ...rows.map((r) => r.risk.length));

  lines.push(
    pc.dim(
      `  ${"drop".padEnd(4)}  ${"package".padEnd(pkgW)}  ${"size↓".padEnd(sizeW)}  ${"risk".padEnd(riskW)}  ${"action".padEnd(11)}  drop = 0.40·own + 0.35·self + 0.25·ftpt`,
    ),
  );
  for (const { d, pkg, size, risk } of rows) {
    const drop = paintDropValue(d.dropScore, String(d.dropScore).padStart(4));
    const riskPaint = d.deprecated
      ? pc.red
      : d.advisoryCount === 0
        ? pc.dim
        : paintRiskColor(d.severity);
    lines.push(
      `  ${drop}  ${pkg.padEnd(pkgW)}  ${cell(size, sizeW, pc.dim)}  ${cell(
        risk,
        riskW,
        riskPaint,
      )}  ${cell(d.verdict, 11, VERDICT_COLOR[d.verdict])}  ${pc.dim(dropBreakdown(d))}`,
    );
  }
  if (deps.length > shown.length) {
    lines.push(pc.dim(`  … and ${deps.length - shown.length} more`));
  }
  return lines;
}

export function renderAudit(report: AuditReport, top: number): string {
  const { target } = report;
  const lines: string[] = [];
  lines.push("");
  lines.push(
    `${pc.bold("Dependency audit")} — ${pc.bold(target.name)}${pc.dim("@")}${target.version}`,
  );
  const capped =
    report.evaluated < report.totalDependencies
      ? ` (evaluated ${report.evaluated}, capped)`
      : "";
  lines.push(
    pc.dim(
      `${report.totalDependencies} dependencies${capped}. Ranked by how worthwhile it is to drop each one.`,
    ),
  );
  lines.push("");

  if (report.ranking.length === 0) {
    lines.push(pc.green("  No dependencies — nothing to drop. 🎉"));
    lines.push("");
    return lines.join("\n");
  }

  // dependencies and devDependencies have different risk profiles (devDeps are
  // build-time, not shipped), so they're ranked in separate sections.
  const prod = report.ranking.filter((d) => !d.dev);
  const dev = report.ranking.filter((d) => d.dev);

  if (dev.length && prod.length) {
    lines.push(pc.bold("  dependencies"));
    lines.push(...auditTable(prod, top));
    lines.push("");
    lines.push(pc.bold("  devDependencies"));
    lines.push(...auditTable(dev, top));
  } else {
    lines.push(...auditTable(report.ranking, top));
  }

  lines.push("");
  lines.push(
    pc.dim(
      "  drop = 0.40·own + 0.35·self + 0.25·ftpt (each /100): own = small own code, " +
        "self = few transitive deps, ftpt = light install footprint (sensitive caps it low). " +
        "Deprecated/advisories are a separate axis (listed first); ⚙ = install scripts; " +
        "size↓ = install weight uniquely shed.",
    ),
  );
  lines.push("");
  return lines.join("\n");
}

export function renderCommons(report: CommonsReport, top: number): string {
  const lines: string[] = [];
  lines.push("");
  lines.push(
    `${pc.bold("Common dependencies")} across ${pc.bold(String(report.packages.length))} packages`,
  );
  lines.push(pc.dim(`  ${report.packages.join(", ")}`));
  lines.push("");

  if (report.deps.length === 0) {
    lines.push(pc.dim("  No dependencies shared across your packages."));
    lines.push("");
    return lines.join("\n");
  }

  const shown = report.deps.slice(0, top);
  const rows = shown.map((d) => ({
    d,
    pkg: `${d.name}@${d.version}${d.dev ? " (dev)" : ""}`,
    used: `${d.usageCount}×`,
    size:
      d.footprintBytes !== undefined
        ? humanBytes(d.footprintBytes) + (d.footprintApprox ? "+" : "")
        : "?",
  }));
  const pkgW = Math.max(7, ...rows.map((r) => r.pkg.length));
  const usedW = Math.max(4, ...rows.map((r) => r.used.length));
  const sizeW = Math.max(6, ...rows.map((r) => r.size.length));

  lines.push(
    pc.dim(
      `  ${"value".padEnd(5)}  ${"package".padEnd(pkgW)}  ${"used".padEnd(usedW)}  ${"size".padEnd(sizeW)}  ${"action".padEnd(11)}  why`,
    ),
  );
  for (const { d, pkg, used, size } of rows) {
    const value = paintDropValue(d.commonsScore, String(d.commonsScore).padStart(5));
    lines.push(
      `  ${value}  ${pkg.padEnd(pkgW)}  ${cell(used, usedW, pc.bold)}  ${cell(size, sizeW, pc.dim)}  ${cell(
        d.verdict,
        11,
        VERDICT_COLOR[d.verdict],
      )}  ${pc.dim(d.reasons.join("; "))}`,
    );
  }
  if (report.deps.length > shown.length) {
    lines.push(pc.dim(`  … and ${report.deps.length - shown.length} more`));
  }
  lines.push("");
  lines.push(
    pc.dim(
      "  value = reimplementation payoff = inline-ability × how many of your packages use it. " +
        "Reimplement once internally, drop everywhere. used = # of your packages.",
    ),
  );
  lines.push("");
  return lines.join("\n");
}

function paintRiskColor(level: RiskLevel): (s: string) => string {
  switch (level) {
    case "low":
      return pc.green;
    case "medium":
      return pc.yellow;
    case "high":
    case "critical":
      return pc.red;
    default:
      return pc.dim;
  }
}
