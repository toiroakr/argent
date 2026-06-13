export interface PackageSpec {
  name: string;
  version?: string;
}

/**
 * Parses an npm package spec, handling scoped names.
 *   "express"            -> { name: "express" }
 *   "express@4.18.2"     -> { name: "express", version: "4.18.2" }
 *   "@scope/pkg@1.0.0"   -> { name: "@scope/pkg", version: "1.0.0" }
 */
export function parseSpec(input: string): PackageSpec {
  const at = input.lastIndexOf("@");
  if (at <= 0) return { name: input };
  return { name: input.slice(0, at), version: input.slice(at + 1) };
}
