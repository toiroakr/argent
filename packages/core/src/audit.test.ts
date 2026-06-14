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

test("a thin wrapper dragging a big tree outranks a pure tiny leaf", () => {
  const leaf = scoreDrop(base);
  const wrapper = scoreDrop({
    ...base,
    ownBytes: 30_000,
    footprintBytes: 1_600_000,
    transitiveDeps: 43,
  });
  expect(wrapper).toBeGreaterThan(leaf);
});

test("clean deps still produce a spread (not one bucket)", () => {
  const tiny = scoreDrop(base);
  const heavy = scoreDrop({ ...base, footprintBytes: 2_000_000, transitiveDeps: 20 });
  expect(heavy).not.toBe(tiny);
});

test("security-sensitive lowers the inline component", () => {
  expect(scoreDrop({ ...base, sensitive: true })).toBeLessThan(scoreDrop(base));
});

test("large own code is less inline-able than tiny own code", () => {
  const tiny = scoreDrop({ ...base, ownBytes: 3_000 });
  const big = scoreDrop({ ...base, ownBytes: 1_500_000 });
  expect(tiny).toBeGreaterThan(big);
});
