import { getJson } from "../http.js";
import { levelFromScore } from "../risk.js";
import type { Provider, ProviderFinding, ProviderResult } from "../types.js";

const BASE = "https://api.socket.dev/v0";

interface SocketScore {
  // Each category exposes a 0..1 score; higher is safer.
  supplyChainRisk?: { score: number };
  quality?: { score: number };
  maintenance?: { score: number };
  vulnerability?: { score: number };
  license?: { score: number };
}

const CATEGORIES: { key: keyof SocketScore; label: string }[] = [
  { key: "supplyChainRisk", label: "Supply chain" },
  { key: "vulnerability", label: "Vulnerability" },
  { key: "maintenance", label: "Maintenance" },
  { key: "quality", label: "Quality" },
  { key: "license", label: "License" },
];

/** Base64 that works in both Node and the browser. */
function base64(input: string): string {
  if (typeof globalThis.btoa === "function") return globalThis.btoa(input);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return (globalThis as any).Buffer.from(input).toString("base64");
}

/**
 * socket.dev computes supply-chain risk scores from static analysis of the
 * package. The API requires a token, so this is skipped in the browser and
 * when no key is configured (the UI links out instead).
 */
export const socketProvider: Provider = {
  id: "socket.dev",
  browserSafe: false,
  async evaluate(ctx): Promise<ProviderResult> {
    const url = `https://socket.dev/npm/package/${ctx.name}/overview/${ctx.version}`;
    const base = { provider: "socket.dev", url };

    if (!ctx.config.socketApiKey) {
      return {
        ...base,
        ok: false,
        skipped: true,
        level: "unknown",
        summary: "Skipped — set SOCKET_API_KEY to enable",
        findings: [],
      };
    }

    try {
      const data = await getJson<SocketScore>(
        `${BASE}/npm/${encodeURIComponent(ctx.name)}/${encodeURIComponent(ctx.version)}/score`,
        {
          fetch: ctx.fetch,
          headers: {
            authorization: `Basic ${base64(`${ctx.config.socketApiKey}:`)}`,
          },
        },
      );

      const findings: ProviderFinding[] = [];
      const scores: number[] = [];
      for (const { key, label } of CATEGORIES) {
        const raw = data[key]?.score;
        if (typeof raw !== "number") continue;
        const pct = Math.round(raw * 100);
        scores.push(pct);
        findings.push({ label, value: `${pct}/100`, level: levelFromScore(pct) });
      }

      const overall = scores.length
        ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length)
        : undefined;

      return {
        ...base,
        ok: true,
        score: overall,
        level: overall === undefined ? "unknown" : levelFromScore(overall),
        summary:
          overall === undefined
            ? "socket.dev returned no scores"
            : `socket.dev overall ${overall}/100`,
        findings,
      };
    } catch (err) {
      return {
        ...base,
        ok: false,
        level: "unknown",
        summary: "socket.dev lookup failed",
        findings: [],
        error: err instanceof Error ? err.message : String(err),
      };
    }
  },
};
