import { expect, test } from "vitest";
import { medianCloseDays, parseGithub } from "./github.js";

test("parseGithub extracts owner/repo for GitHub repos only", () => {
  expect(parseGithub("github.com/expressjs/express")).toEqual({
    owner: "expressjs",
    repo: "express",
  });
  expect(parseGithub("github.com/a/b.git")).toEqual({ owner: "a", repo: "b" });
  expect(parseGithub("gitlab.com/a/b")).toBeUndefined();
  expect(parseGithub(undefined)).toBeUndefined();
});

const issue = (created: string, closed: string | null, isPr = false) => ({
  created_at: created,
  closed_at: closed,
  ...(isPr ? { pull_request: {} } : {}),
});

test("medianCloseDays excludes PRs and still-open issues", () => {
  const median = medianCloseDays([
    issue("2024-01-01T00:00:00Z", "2024-01-03T00:00:00Z"), // 2d
    issue("2024-01-01T00:00:00Z", null), // open — excluded
    issue("2024-01-01T00:00:00Z", "2024-01-21T00:00:00Z", true), // PR — excluded
  ]);
  expect(median).toBe(2);
});

test("medianCloseDays averages the two middle values for an even count", () => {
  const median = medianCloseDays([
    issue("2024-01-01T00:00:00Z", "2024-01-05T00:00:00Z"), // 4d
    issue("2024-01-01T00:00:00Z", "2024-01-03T00:00:00Z"), // 2d
  ]);
  expect(median).toBe(3); // (2 + 4) / 2
});

test("medianCloseDays returns undefined when there's nothing to measure", () => {
  expect(medianCloseDays([])).toBeUndefined();
  expect(medianCloseDays([issue("2024-01-01T00:00:00Z", null)])).toBeUndefined();
});
