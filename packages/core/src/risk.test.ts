import { expect, test } from "vitest";
import {
  aggregate,
  levelFromAdvisories,
  levelFromScore,
  levelFromSeverity,
  worse,
} from "./risk.js";

test("worse picks the more severe level", () => {
  expect(worse("low", "high")).toBe("high");
  expect(worse("critical", "medium")).toBe("critical");
  expect(worse("unknown", "low")).toBe("low");
});

test("aggregate ignores unknown unless everything is unknown", () => {
  expect(aggregate(["unknown", "low", "medium"])).toBe("medium");
  expect(aggregate(["unknown", "unknown"])).toBe("unknown");
  expect(aggregate([])).toBe("unknown");
});

test("levelFromScore maps thresholds", () => {
  expect(levelFromScore(95)).toBe("low");
  expect(levelFromScore(70)).toBe("medium");
  expect(levelFromScore(50)).toBe("high");
  expect(levelFromScore(10)).toBe("critical");
});

test("levelFromSeverity normalizes provider strings", () => {
  expect(levelFromSeverity("CRITICAL")).toBe("critical");
  expect(levelFromSeverity("moderate")).toBe("medium");
  expect(levelFromSeverity(undefined)).toBe("unknown");
});

test("levelFromAdvisories: no advisories is low", () => {
  expect(levelFromAdvisories([])).toBe("low");
});

test("levelFromAdvisories: worst real severity wins", () => {
  expect(levelFromAdvisories(["low", "high", "medium"])).toBe("high");
  expect(levelFromAdvisories(["unknown", "critical"])).toBe("critical");
});

test("levelFromAdvisories: present-but-unparseable advisories floor to medium", () => {
  // The bug this guards: aggregate() discards "unknown", so a known advisory
  // with no parseable severity must not silently vanish from the overall risk.
  expect(levelFromAdvisories(["unknown"])).toBe("medium");
  expect(levelFromAdvisories(["unknown", "unknown"])).toBe("medium");
});
