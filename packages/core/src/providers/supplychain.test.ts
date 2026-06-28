import { expect, test } from "vitest";
import type { EvalContext } from "../types.js";
import { supplyChainProvider } from "./supplychain.js";

/** A SLSA provenance attestation bundle for `attestedRepo`, as npm serves it. */
function attestationBundle(attestedRepo: string): unknown {
  const statement = {
    predicateType: "https://slsa.dev/provenance/v1",
    predicate: {
      buildDefinition: { externalParameters: { workflow: { repository: attestedRepo } } },
    },
  };
  const payload = Buffer.from(JSON.stringify(statement)).toString("base64");
  return { attestations: [{ bundle: { dsseEnvelope: { payload } } }] };
}

/**
 * Routes by URL substring, in insertion order so the attestation route (also on
 * registry.npmjs.org) is matched before the generic package-doc route.
 */
function mockFetch(routes: [match: string, body: unknown][]): typeof fetch {
  return (async (url: string | URL) => {
    const u = String(url);
    const hit = routes.find(([m]) => u.includes(m));
    if (!hit) return { ok: false, status: 404, json: async () => ({}) } as unknown as Response;
    return { ok: true, status: 200, json: async () => hit[1] } as unknown as Response;
  }) as typeof fetch;
}

function ctx(fetchImpl: typeof fetch, repoUrl?: string): EvalContext {
  return {
    name: "demo",
    version: "1.0.0",
    repoUrl,
    fetch: fetchImpl,
    config: { browser: false },
  };
}

const doc = (version: Record<string, unknown>, maintainers = 2): unknown => ({
  maintainers: Array.from({ length: maintainers }, (_, i) => ({ name: `m${i}` })),
  versions: { "1.0.0": version },
});

test("clean package with multiple maintainers is low", async () => {
  const f = mockFetch([["attestations", { attestations: [] }], ["demo", doc({})]]);
  const r = await supplyChainProvider.evaluate(ctx(f));
  expect(r.ok).toBe(true);
  expect(r.level).toBe("low");
});

test("a deprecated package is high", async () => {
  const f = mockFetch([
    ["attestations", { attestations: [] }],
    ["demo", doc({ deprecated: "no longer maintained" })],
  ]);
  const r = await supplyChainProvider.evaluate(ctx(f));
  expect(r.level).toBe("high");
  expect(r.summary).toMatch(/deprecated/i);
});

test("install scripts raise the level to medium", async () => {
  const f = mockFetch([
    ["attestations", { attestations: [] }],
    ["demo", doc({ scripts: { postinstall: "node build.js" } })],
  ]);
  const r = await supplyChainProvider.evaluate(ctx(f));
  expect(r.level).toBe("medium");
  expect(r.findings).toContainEqual(
    expect.objectContaining({ label: "Install scripts", value: "postinstall" }),
  );
});

test("a lone maintainer is surfaced as a caution but not an alarm", async () => {
  const f = mockFetch([["attestations", { attestations: [] }], ["demo", doc({}, 1)]]);
  const r = await supplyChainProvider.evaluate(ctx(f));
  expect(r.level).toBe("low");
  expect(r.findings).toContainEqual(
    expect.objectContaining({ label: "Maintainers", value: "1", level: "medium" }),
  );
});

test("provenance that matches the linked repo is verified and stays low", async () => {
  const f = mockFetch([
    ["attestations", attestationBundle("https://github.com/demo/demo")],
    ["demo", doc({ dist: { attestations: { provenance: { predicateType: "x" } } } })],
  ]);
  const r = await supplyChainProvider.evaluate(ctx(f, "github.com/demo/demo"));
  expect(r.level).toBe("low");
  expect(r.findings).toContainEqual(
    expect.objectContaining({ label: "Build provenance", value: "yes (repo verified)" }),
  );
});

test("provenance attesting a DIFFERENT repo is flagged high (spoofing)", async () => {
  const f = mockFetch([
    ["attestations", attestationBundle("https://github.com/attacker/evil")],
    ["demo", doc({ dist: { attestations: { provenance: { predicateType: "x" } } } })],
  ]);
  // The package links to a popular repo it wasn't actually built from.
  const r = await supplyChainProvider.evaluate(ctx(f, "github.com/popular/lib"));
  expect(r.level).toBe("high");
  expect(r.summary).toMatch(/mismatch|spoof/i);
  expect(r.findings).toContainEqual(
    expect.objectContaining({ label: "Build provenance", level: "high" }),
  );
});
