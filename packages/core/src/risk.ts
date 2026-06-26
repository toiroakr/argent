import type { RiskLevel } from "./types.js";

const ORDER: Record<RiskLevel, number> = {
  unknown: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

/** Returns the more severe of two levels; "unknown" never overrides a real one. */
export function worse(a: RiskLevel, b: RiskLevel): RiskLevel {
  return ORDER[a] >= ORDER[b] ? a : b;
}

/** Reduces a set of levels to the single worst real level (ignoring unknown). */
export function aggregate(levels: RiskLevel[]): RiskLevel {
  const real = levels.filter((l) => l !== "unknown");
  if (real.length === 0) return "unknown";
  return real.reduce<RiskLevel>((acc, l) => worse(acc, l), "low");
}

/**
 * Maps a 0-100 "safer is higher" score to a risk level.
 * Thresholds are intentionally conservative for supply-chain use.
 */
export function levelFromScore(score: number): RiskLevel {
  if (score >= 80) return "low";
  if (score >= 60) return "medium";
  if (score >= 40) return "high";
  return "critical";
}

/**
 * Risk level for a package given the normalized severities of its known
 * advisories. An empty list means "no advisories" → "low". Otherwise the worst
 * severity — but a present advisory whose severity we couldn't parse must NOT be
 * silently dropped: plain `aggregate()` discards "unknown", so an all-unknown
 * set (advisories exist, severities unparseable) floors to "medium" rather than
 * vanishing from the overall risk.
 */
export function levelFromAdvisories(severities: RiskLevel[]): RiskLevel {
  if (severities.length === 0) return "low";
  const level = aggregate(severities);
  return level === "unknown" ? "medium" : level;
}

/** CVSS-style severity string -> normalized level. */
export function levelFromSeverity(severity: string | undefined): RiskLevel {
  switch ((severity ?? "").toUpperCase()) {
    case "CRITICAL":
      return "critical";
    case "HIGH":
      return "high";
    case "MEDIUM":
    case "MODERATE":
      return "medium";
    case "LOW":
      return "low";
    default:
      return "unknown";
  }
}
