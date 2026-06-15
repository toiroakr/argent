import { expect, test } from "vitest";
import { classifyLicense } from "./license.js";

test("permissive licenses", () => {
  for (const id of ["MIT", "ISC", "BSD-3-Clause", "Apache-2.0", "0BSD"]) {
    expect(classifyLicense(id).category).toBe("permissive");
    expect(classifyLicense(id).level).toBe("low");
  }
});

test("copyleft tiers", () => {
  expect(classifyLicense("LGPL-3.0").category).toBe("weak-copyleft");
  expect(classifyLicense("GPL-3.0-only").category).toBe("strong-copyleft");
  expect(classifyLicense("AGPL-3.0").category).toBe("network-copyleft");
  expect(classifyLicense("AGPL-3.0").level).toBe("high");
});

test("missing / proprietary", () => {
  expect(classifyLicense(undefined).category).toBe("none");
  expect(classifyLicense("UNLICENSED").category).toBe("proprietary");
  expect(classifyLicense("SEE LICENSE IN LICENSE.txt").category).toBe("unknown");
});
