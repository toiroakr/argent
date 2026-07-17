import { expect, test } from "vitest";
import type { EvalContext } from "../types.js";
import {
  findSensitiveTerms,
  recommendBuildVsBuy,
  reimplementabilityProvider,
} from "./reimplementability.js";

function mockFetch(routes: [match: string, body: unknown][]): typeof fetch {
  return (async (url: string | URL) => {
    const u = String(url);
    const hit = routes.find(([m]) => u.includes(m));
    if (!hit) return { ok: false, status: 404, json: async () => ({}) } as unknown as Response;
    return { ok: true, status: 200, json: async () => hit[1] } as unknown as Response;
  }) as typeof fetch;
}

function ctx(fetchImpl: typeof fetch): EvalContext {
  return {
    name: "demo",
    version: "1.0.0",
    fetch: fetchImpl,
    config: { browser: false },
  };
}

const npmDoc = (deps: Record<string, string>, dist: Record<string, unknown>): unknown => ({
  versions: { "1.0.0": { dependencies: deps, dist } },
});

test("tiny self-contained package -> reimplement", () => {
  const v = recommendBuildVsBuy({
    unpackedSize: 6_510,
    fileCount: 4,
    directDeps: 0,
    transitiveDeps: 0,
    sensitiveHits: [],
  });
  expect(v.verdict).toBe("reimplement");
  expect(v.level).toBe("high");
});

test("small package with a few deps -> consider", () => {
  const v = recommendBuildVsBuy({
    unpackedSize: 80 * 1024,
    fileCount: 20,
    transitiveDeps: 2,
    sensitiveHits: [],
  });
  expect(v.verdict).toBe("consider");
  expect(v.level).toBe("medium");
});

test("large package -> keep", () => {
  const v = recommendBuildVsBuy({
    unpackedSize: 5 * 1024 * 1024,
    transitiveDeps: 40,
    sensitiveHits: [],
  });
  expect(v.verdict).toBe("keep");
  expect(v.level).toBe("low");
});

test("security-sensitive domain always -> keep, even if tiny", () => {
  const v = recommendBuildVsBuy({
    unpackedSize: 2_000,
    fileCount: 2,
    transitiveDeps: 0,
    sensitiveHits: ["jwt"],
  });
  expect(v.verdict).toBe("keep");
  expect(v.level).toBe("low");
  expect(v.recommendation).toMatch(/sensitive/i);
});

test("missing metrics -> unknown", () => {
  const v = recommendBuildVsBuy({ sensitiveHits: [] });
  expect(v.verdict).toBe("unknown");
  expect(v.level).toBe("unknown");
});

test("thin body + one heavy direct dep among light ones -> partial, naming the heavy one", () => {
  const v = recommendBuildVsBuy({
    unpackedSize: 4_000,
    fileCount: 3,
    directDepWeights: [
      { name: "heavy-lib", version: "1.0.0", footprintBytes: 900 * 1024 },
      { name: "tiny-helper", version: "1.0.0", footprintBytes: 2_000 },
    ],
    sensitiveHits: [],
  });
  expect(v.verdict).toBe("partial");
  expect(v.level).toBe("medium");
  expect(v.keepDeps).toEqual(["heavy-lib"]);
  expect(v.recommendation).toMatch(/heavy-lib/);
});

test("thin body + all direct deps light (weighted) -> reimplement", () => {
  const v = recommendBuildVsBuy({
    unpackedSize: 4_000,
    fileCount: 3,
    directDepWeights: [
      { name: "tiny-helper-a", version: "1.0.0", footprintBytes: 1_000 },
      { name: "tiny-helper-b", version: "1.0.0", footprintBytes: 2_000 },
    ],
    sensitiveHits: [],
  });
  expect(v.verdict).toBe("reimplement");
  expect(v.level).toBe("high");
});

test("thin body + every direct dep heavy (weighted) -> keep", () => {
  const v = recommendBuildVsBuy({
    unpackedSize: 4_000,
    fileCount: 3,
    directDepWeights: [
      { name: "heavy-a", version: "1.0.0", footprintBytes: 900 * 1024 },
      { name: "heavy-b", version: "1.0.0", footprintBytes: 900 * 1024 },
    ],
    sensitiveHits: [],
  });
  expect(v.verdict).toBe("keep");
  expect(v.level).toBe("low");
});

test("sensitive domain still wins over a weighted breakdown", () => {
  const v = recommendBuildVsBuy({
    unpackedSize: 4_000,
    directDepWeights: [{ name: "tiny-helper", version: "1.0.0", footprintBytes: 1_000 }],
    sensitiveHits: ["jwt"],
  });
  expect(v.verdict).toBe("keep");
  expect(v.recommendation).toMatch(/sensitive/i);
});

test("findSensitiveTerms matches whole words, not substrings", () => {
  expect(findSensitiveTerms("jsonwebtoken", ["jwt"], "Sign and verify JWTs")).toContain("jwt");
  expect(findSensitiveTerms("left-pad", [], "Pad a string")).toEqual([]);
  // "author" must not trigger the "auth" term.
  expect(findSensitiveTerms("my-lib", [], "Written by the author")).toEqual([]);
});

test("provider: resolves per-direct-dep exclusive footprint from the deps.dev graph -> partial", async () => {
  const graph = {
    nodes: [
      { versionKey: { name: "demo", version: "1.0.0" }, relation: "SELF" },
      { versionKey: { name: "heavy-lib", version: "1.0.0" }, relation: "DIRECT" },
      { versionKey: { name: "tiny-helper", version: "1.0.0" }, relation: "DIRECT" },
      { versionKey: { name: "sub-dep", version: "1.0.0" }, relation: "INDIRECT" },
    ],
    edges: [
      { fromNode: 0, toNode: 1 },
      { fromNode: 0, toNode: 2 },
      { fromNode: 1, toNode: 3 },
    ],
  };
  const f = mockFetch([
    ["registry.npmjs.org/demo", npmDoc({ "heavy-lib": "^1.0.0", "tiny-helper": "^1.0.0" }, { unpackedSize: 4_000, fileCount: 3 })],
    ["registry.npmjs.org/heavy-lib", npmDoc({}, { unpackedSize: 10_000 })],
    ["registry.npmjs.org/tiny-helper", npmDoc({}, { unpackedSize: 2_000 })],
    ["registry.npmjs.org/sub-dep", npmDoc({}, { unpackedSize: 900_000 })],
    [":dependencies", graph],
  ]);

  const r = await reimplementabilityProvider.evaluate(ctx(f));

  expect(r.ok).toBe(true);
  expect(r.level).toBe("medium");
  expect(r.summary).toMatch(/partial|heavy-lib/i);
  // heavy-lib's exclusive footprint (itself + sub-dep, which only it reaches) is
  // reported as heavy; tiny-helper (no children) is reported as light.
  expect(r.findings).toContainEqual(
    expect.objectContaining({ label: "↳ heavy-lib", level: "medium" }),
  );
  expect(r.findings).toContainEqual(
    expect.objectContaining({ label: "↳ tiny-helper", level: "low" }),
  );
});
