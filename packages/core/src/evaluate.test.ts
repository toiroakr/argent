import { expect, test } from "vitest";
import { coverageOf } from "./evaluate.js";
import type { ProviderResult } from "./types.js";

/** Minimal ProviderResult builder for coverage classification tests. */
function res(p: Partial<ProviderResult> & { provider: string }): ProviderResult {
  return { ok: true, level: "low", summary: "", findings: [], ...p };
}

test("coverageOf ignores advisory axes entirely", () => {
  const cov = coverageOf([
    res({ provider: "deps.dev", level: "low" }),
    res({ provider: "Build-vs-Buy", advisory: true, level: "high" }),
    res({ provider: "License", advisory: true, level: "medium" }),
  ]);
  expect(cov).toEqual({ evaluated: 1, total: 1, missing: [] });
});

test("coverageOf classifies why each security source didn't contribute", () => {
  const cov = coverageOf([
    res({ provider: "deps.dev", ok: true, level: "low" }), // contributes
    res({ provider: "OpenSSF Scorecard", ok: false, skipped: true, level: "unknown" }), // skipped
    res({ provider: "Snyk Advisor", ok: false, level: "unknown" }), // error
    res({ provider: "socket.dev", ok: true, level: "unknown" }), // ran but no signal
    res({ provider: "Community", advisory: true, ok: false, level: "unknown" }), // advisory: ignored
  ]);
  expect(cov.total).toBe(4);
  expect(cov.evaluated).toBe(1);
  expect(cov.missing).toEqual([
    { provider: "OpenSSF Scorecard", reason: "skipped" },
    { provider: "Snyk Advisor", reason: "error" },
    { provider: "socket.dev", reason: "unknown" },
  ]);
});

test("coverageOf reports full coverage when every security source contributes", () => {
  const cov = coverageOf([
    res({ provider: "deps.dev", level: "low" }),
    res({ provider: "Supply Chain", level: "medium" }),
  ]);
  expect(cov).toEqual({ evaluated: 2, total: 2, missing: [] });
});
