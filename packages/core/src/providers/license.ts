import { getJson } from "../http.js";
import { REGISTRY, type RegistryDoc } from "../npm.js";
import type { Provider, ProviderResult, RiskLevel } from "../types.js";

export type LicenseCategory =
  | "permissive"
  | "weak-copyleft"
  | "strong-copyleft"
  | "network-copyleft"
  | "proprietary"
  | "none"
  | "unknown";

/**
 * Classifies an SPDX-ish license id into an adoption/legal category. This is a
 * legal obligation signal, not a security one.
 */
export function classifyLicense(id: string | undefined): {
  category: LicenseCategory;
  level: RiskLevel;
} {
  const s = (id ?? "").trim().toUpperCase();
  if (!s || s === "UNLICENSED") return { category: s === "UNLICENSED" ? "proprietary" : "none", level: "medium" };
  if (/\bAGPL/.test(s)) return { category: "network-copyleft", level: "high" };
  if (/\bGPL/.test(s)) return { category: "strong-copyleft", level: "medium" };
  if (/\b(LGPL|MPL|EPL|CDDL|EUPL)/.test(s)) return { category: "weak-copyleft", level: "low" };
  if (/\b(MIT|ISC|BSD|APACHE|0BSD|UNLICENSE|CC0|WTFPL|ZLIB|BLUEOAK|PYTHON|MIT-0)/.test(s))
    return { category: "permissive", level: "low" };
  if (s === "SEE LICENSE IN" || s.startsWith("SEE LICENSE")) return { category: "unknown", level: "medium" };
  return { category: "unknown", level: "unknown" };
}

interface FullDoc extends RegistryDoc {
  license?: string | { type?: string };
  versions: RegistryDoc["versions"] & Record<string, { license?: string | { type?: string } }>;
}

function readLicense(doc: FullDoc, version: string): string | undefined {
  const raw = doc.versions?.[version]?.license ?? doc.license;
  if (!raw) return undefined;
  return typeof raw === "string" ? raw : raw.type;
}

/**
 * Reports the package's license and its obligation category (permissive vs
 * copyleft vs none). Advisory — a legal/adoption concern, excluded from the
 * security overall. CORS-safe.
 */
export const licenseProvider: Provider = {
  id: "License",
  browserSafe: true,
  async evaluate(ctx): Promise<ProviderResult> {
    const base = { provider: "License", advisory: true };
    try {
      const doc = await getJson<FullDoc>(`${REGISTRY}/${encodeURIComponent(ctx.name)}`, {
        fetch: ctx.fetch,
      });
      const id = readLicense(doc, ctx.version);
      const { category, level } = classifyLicense(id);
      const display = id ?? "none declared";
      const summary =
        category === "none"
          ? "No license — all rights reserved by default"
          : category === "network-copyleft"
            ? `${display} — network copyleft (affects SaaS use)`
            : category === "strong-copyleft"
              ? `${display} — copyleft (derivative works must be open)`
              : `${display} (${category.replace("-", " ")})`;
      return { ...base, ok: true, level, summary, findings: [] };
    } catch (err) {
      return {
        ...base,
        ok: false,
        level: "unknown",
        summary: "License lookup failed",
        findings: [],
        error: err instanceof Error ? err.message : String(err),
      };
    }
  },
};
