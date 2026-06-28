import { expect, test } from "vitest";
import { pickRepo } from "./depsdev.js";

test("pickRepo prefers a related source-project id", () => {
  expect(
    pickRepo({
      relatedProjects: [{ projectKey: { id: "github.com/a/b" }, relationType: "SOURCE_REPO" }],
    }),
  ).toBe("github.com/a/b");
});

test("pickRepo falls back to a repo link and normalizes it", () => {
  expect(
    pickRepo({ links: [{ label: "Source", url: "https://github.com/a/b.git#readme" }] }),
  ).toBe("github.com/a/b");
});

test("pickRepo ignores non-repo links and projects", () => {
  expect(pickRepo({ links: [{ label: "Homepage", url: "https://example.com/x" }] })).toBeUndefined();
  expect(pickRepo({})).toBeUndefined();
});
