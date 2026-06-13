import { expect, test } from "vitest";
import { aggregate, levelFromScore, levelFromSeverity, worse } from "./risk.js";

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
