import { existsSync, readFileSync } from "node:fs";
import { dirname, join, parse } from "node:path";
import type { AuditEntry } from "@argent/core";
// Note: dependency versions are intentionally resolved to the registry's latest
// (by the core auditor) rather than read from node_modules — auditing the
// version you'd actually move toward is both simpler and more useful.

export interface LoadedManifest {
  /** Project name (or a placeholder when missing). */
  name: string;
  version: string;
  /** Absolute path to the package.json that was used. */
  path: string;
  entries: AuditEntry[];
}

/** Walks up from `start` to find the nearest package.json. */
export function findManifest(start: string): string | undefined {
  let dir = start;
  const root = parse(dir).root;
  while (true) {
    const candidate = join(dir, "package.json");
    if (existsSync(candidate)) return candidate;
    if (dir === root) return undefined;
    dir = dirname(dir);
  }
}

/**
 * Loads dependency entries from a package.json. Versions are left undefined so
 * the core auditor resolves each to the registry's latest.
 */
export function loadManifest(
  manifestPath: string,
  includeDev: boolean,
): LoadedManifest {
  const pkg = JSON.parse(readFileSync(manifestPath, "utf8")) as {
    name?: string;
    version?: string;
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
  };

  const entries: AuditEntry[] = [];
  const add = (deps: Record<string, string> | undefined, dev: boolean) => {
    for (const name of Object.keys(deps ?? {})) entries.push({ name, dev });
  };
  add(pkg.dependencies, false);
  if (includeDev) add(pkg.devDependencies, true);

  return {
    name: pkg.name ?? "(this project)",
    version: pkg.version ?? "0.0.0",
    path: manifestPath,
    entries,
  };
}
