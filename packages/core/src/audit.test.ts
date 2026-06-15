import { expect, test } from "vitest";
import { scoreDrop } from "./audit.js";

const base = {
  sensitive: false,
  ownBytes: 8_000,
  footprintBytes: 8_000,
  transitiveDeps: 0,
};

// dropScore is an adoption signal only — vulnerabilities are a separate axis,
// so they are intentionally NOT an input here.

test("a tiny self-contained utility is the best drop candidate", () => {
  expect(scoreDrop({ ...base, ownBytes: 2_000, footprintBytes: 5_000 })).toBeGreaterThan(70);
});

test("a thin wrapper over a big tree is NOT easy to drop", () => {
  const leaf = scoreDrop(base);
  const wrapper = scoreDrop({
    ...base,
    ownBytes: 30_000,
    footprintBytes: 1_600_000,
    transitiveDeps: 43,
  });
  // The wrapper's own code is small, but its big subtree makes it hard to escape.
  expect(wrapper).toBeLessThan(leaf);
});

test("more transitive deps lower the score (less self-contained)", () => {
  const fewer = scoreDrop({ ...base, transitiveDeps: 1 });
  const more = scoreDrop({ ...base, transitiveDeps: 10, footprintBytes: 800_000 });
  expect(more).toBeLessThan(fewer);
});

test("large own code is harder to reimplement", () => {
  const tiny = scoreDrop({ ...base, ownBytes: 3_000 });
  const big = scoreDrop({ ...base, ownBytes: 400_000 });
  expect(tiny).toBeGreaterThan(big);
});

test("security-sensitive scores low regardless of size", () => {
  expect(scoreDrop({ ...base, sensitive: true })).toBeLessThanOrEqual(15);
});
