import { expect, test } from "vitest";
import { extractScore } from "./snyk.js";

test("extractScore prefers the structured __NEXT_DATA__ blob", () => {
  const html = `<script id="__NEXT_DATA__" type="application/json">{"props":{"score":78}}</script>`;
  expect(extractScore(html)).toBe(78);
});

test("extractScore falls back to the rendered number class", () => {
  expect(extractScore('<div class="health number big"> 85 </div>')).toBe(85);
});

test("extractScore falls back to an N / 100 label", () => {
  expect(extractScore("<p>Package health score: 92 / 100</p>")).toBe(92);
});

test("extractScore returns undefined when the markup has no score", () => {
  // Scraping is best-effort: a markup change must yield "unknown", not a guess.
  expect(extractScore("<html><body>no score here</body></html>")).toBeUndefined();
});

test("extractScore rejects out-of-range values", () => {
  expect(extractScore(`<script id="__NEXT_DATA__">{"score":150}</script>`)).toBeUndefined();
});
