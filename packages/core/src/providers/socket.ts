import { postText } from "../http.js";
import { levelFromScore } from "../risk.js";
import type { Provider, ProviderFinding, ProviderResult } from "../types.js";

// Current PURL batch endpoint (successor to the deprecated /score route).
// Returns NDJSON, one component per line.
const ENDPOINT = "https://api.socket.dev/v0/purl?alerts=false";

interface SocketScore {
  // Each metric is a 0..1 score; higher is safer. `overall` is provided directly.
  overall?: number;
  supplyChain?: number;
  vulnerability?: number;
  maintenance?: number;
  quality?: number;
  license?: number;
}

interface SocketComponent {
  score?: SocketScore;
}

const CATEGORIES: { key: keyof SocketScore; label: string }[] = [
  { key: "supplyChain", label: "Supply chain" },
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
      const purl = `pkg:npm/${ctx.name}@${ctx.version}`;
      const text = await postText(ENDPOINT, JSON.stringify({ components: [{ purl }] }), {
        fetch: ctx.fetch,
        headers: {
          authorization: `Basic ${base64(`${ctx.config.socketApiKey}:`)}`,
          accept: "application/x-ndjson",
        },
      });

      const line = text.split("\n").find((l) => l.trim());
      const score = line ? (JSON.parse(line) as SocketComponent).score : undefined;

      if (!score) {
        return {
          ...base,
          ok: true,
          level: "unknown",
          summary: "socket.dev returned no scores",
          findings: [],
        };
      }

      const findings: ProviderFinding[] = [];
      for (const { key, label } of CATEGORIES) {
        const raw = score[key];
        if (typeof raw !== "number") continue;
        const pct = Math.round(raw * 100);
        findings.push({ label, value: `${pct}/100`, level: levelFromScore(pct) });
      }

      const overall =
        typeof score.overall === "number" ? Math.round(score.overall * 100) : undefined;

      return {
        ...base,
        ok: true,
        score: overall,
        level: overall === undefined ? "unknown" : levelFromScore(overall),
        summary:
          overall === undefined
            ? "socket.dev returned no overall score"
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
