import { expect, test } from "vitest";
import { normalizeRepo, repoFromStatement, verifyRepo } from "./provenance.js";

test("normalizeRepo reduces URLs/ids to host/org/repo", () => {
  expect(normalizeRepo("https://github.com/Expressjs/Express.git")).toBe(
    "github.com/Expressjs/Express",
  );
  expect(normalizeRepo("git+ssh://git@github.com/a/b.git")).toBe("github.com/a/b");
  expect(normalizeRepo("github.com/a/b")).toBe("github.com/a/b");
  expect(normalizeRepo("https://example.com/a/b")).toBeUndefined();
  expect(normalizeRepo(undefined)).toBeUndefined();
});

test("repoFromStatement pulls the repo from SLSA provenance shapes", () => {
  expect(
    repoFromStatement({
      predicate: {
        buildDefinition: {
          externalParameters: { workflow: { repository: "https://github.com/a/b" } },
        },
      },
    }),
  ).toBe("github.com/a/b");
  expect(
    repoFromStatement({
      predicate: {
        buildDefinition: { resolvedDependencies: [{ uri: "git+https://github.com/c/d.git" }] },
      },
    }),
  ).toBe("github.com/c/d");
  expect(repoFromStatement({})).toBeUndefined();
});

/** Builds a fake fetch returning one npm attestation over the given statement. */
function fetchWith(statement: unknown): typeof fetch {
  const payload = Buffer.from(JSON.stringify(statement)).toString("base64");
  const bundle = {
    attestations: [
      { predicateType: "https://slsa.dev/provenance/v1", bundle: { dsseEnvelope: { payload } } },
    ],
  };
  return (async () =>
    ({ ok: true, json: async () => bundle }) as unknown as Response) as typeof fetch;
}

const provenanceStmt = (repo: string) => ({
  predicate: { buildDefinition: { externalParameters: { workflow: { repository: repo } } } },
});

test("verifyRepo confirms a matching attested repo", async () => {
  const res = await verifyRepo(
    "pkg",
    "1.0.0",
    "github.com/owner/repo",
    fetchWith(provenanceStmt("https://github.com/owner/repo")),
  );
  expect(res).toEqual({ trust: "verified", attestedRepo: "github.com/owner/repo" });
});

test("verifyRepo flags a repo that differs from the attested one (spoofing)", async () => {
  const res = await verifyRepo(
    "pkg",
    "1.0.0",
    "github.com/popular/lib",
    fetchWith(provenanceStmt("https://github.com/attacker/evil")),
  );
  expect(res).toEqual({ trust: "mismatch", attestedRepo: "github.com/attacker/evil" });
});

test("verifyRepo fails open to unverified when there's no attestation", async () => {
  const fetchImpl = (async () =>
    ({ ok: false, status: 404, json: async () => ({}) }) as unknown as Response) as typeof fetch;
  const res = await verifyRepo("pkg", "1.0.0", "github.com/owner/repo", fetchImpl);
  expect(res).toEqual({ trust: "unverified" });
});
