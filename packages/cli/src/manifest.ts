import { existsSync, readFileSync } from "node:fs";
import { dirname, join, parse } from "node:path";
import type { AuditEntry } from "@argent/core";

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

/** Reads the installed version of a dependency from node_modules, if present. */
function installedVersion(dir: string, name: string): string | undefined {
  try {
    const pkg = JSON.parse(
      readFileSync(join(dir, "node_modules", name, "package.json"), "utf8"),
    ) as { version?: string };
    return pkg.version;
  } catch {
    return undefined;
  }
}

/**
 * Loads dependency entries from a package.json. Resolved versions come from the
 * installed copy in node_modules when available; otherwise they are left for
 * the core resolver to fill in from the registry.
 */
export function loadManifest(
  manifestPath: string,
  includeDev: boolean,
): LoadedManifest {
  const dir = dirname(manifestPath);
  const pkg = JSON.parse(readFileSync(manifestPath, "utf8")) as {
    name?: string;
    version?: string;
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
  };

  const entries: AuditEntry[] = [];
  const add = (deps: Record<string, string> | undefined, dev: boolean) => {
    for (const name of Object.keys(deps ?? {})) {
      entries.push({ name, version: installedVersion(dir, name), dev });
    }
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
