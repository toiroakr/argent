import { expect, test } from "vitest";
import {
  findSensitiveTerms,
  recommendBuildVsBuy,
} from "./reimplementability.js";

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

test("findSensitiveTerms matches whole words, not substrings", () => {
  expect(findSensitiveTerms("jsonwebtoken", ["jwt"], "Sign and verify JWTs")).toContain("jwt");
  expect(findSensitiveTerms("left-pad", [], "Pad a string")).toEqual([]);
  // "author" must not trigger the "auth" term.
  expect(findSensitiveTerms("my-lib", [], "Written by the author")).toEqual([]);
});
