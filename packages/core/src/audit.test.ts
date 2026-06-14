import { expect, test } from "vitest";
import { scoreDrop } from "./audit.js";

test("risky + reimplementable ranks highest", () => {
  const risky = scoreDrop(100, "reimplement", false); // critical + tiny
  const cleanHuge = scoreDrop(0, "keep", false);
  const cleanTiny = scoreDrop(0, "reimplement", false);
  expect(risky).toBeGreaterThan(cleanTiny);
  expect(cleanTiny).toBeGreaterThan(cleanHuge);
});

test("sensitive domains are treated as hard to drop", () => {
  const sensitive = scoreDrop(0, "keep", true);
  const reimplementable = scoreDrop(0, "reimplement", false);
  expect(reimplementable).toBeGreaterThan(sensitive);
});

test("clean dependency contributes no risk component", () => {
  // severityScore 0 means only removability matters.
  expect(scoreDrop(0, "keep", false)).toBe(Math.round(0.45 * 15));
});
