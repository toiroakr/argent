import { expect, test } from "vitest";
import { sumSizes } from "./npm.js";

test("sumSizes: no packages is a definite, complete 0", () => {
  // A fully-shared dep sheds nothing uniquely — distinct from "all unknown".
  expect(sumSizes([])).toEqual({ bytes: 0, complete: true });
});

test("sumSizes: all sizes known sums them and stays complete", () => {
  expect(sumSizes([100, 200, 50])).toEqual({ bytes: 350, complete: true });
});

test("sumSizes: a missing size makes the known total a floor", () => {
  expect(sumSizes([100, undefined, 50])).toEqual({ bytes: 150, complete: false });
});

test("sumSizes: every size unknown yields undefined, not a misleading 0", () => {
  expect(sumSizes([undefined, undefined])).toEqual({ bytes: undefined, complete: false });
});
