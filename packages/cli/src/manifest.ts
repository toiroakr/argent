import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join, parse } from "node:path";
import type { AuditEntry, CommonsManifest } from "@argent/core";
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

// --------------------------------------------------------------- workspaces

function readPkg(path: string): Record<string, unknown> | undefined {
  try {
    return JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
  } catch {
    return undefined;
  }
}

/** Extracts workspace globs from a pnpm-workspace.yaml (minimal YAML parsing). */
function pnpmGlobs(yaml: string): string[] {
  const globs: string[] = [];
  let inPackages = false;
  for (const raw of yaml.split("\n")) {
    const line = raw.replace(/#.*$/, "");
    if (/^packages:/.test(line.trim())) {
      inPackages = true;
      continue;
    }
    if (inPackages) {
      const m = line.match(/^\s+-\s*["']?([^"'\s]+)["']?\s*$/);
      if (m?.[1]) globs.push(m[1]);
      else if (line.trim() && !/^\s/.test(raw)) break; // dedent → next top-level key
    }
  }
  return globs;
}

/** Expands a workspace glob (supports `*` and `**`) to dirs under `root`. */
function expandGlob(root: string, pattern: string): string[] {
  const segments = pattern.replace(/\/+$/, "").split("/").filter(Boolean);
  const walk = (base: string, segs: string[]): string[] => {
    if (segs.length === 0) return [base];
    const [seg, ...rest] = segs;
    let dirs: string[];
    try {
      dirs = readdirSync(base, { withFileTypes: true })
        .filter((e) => e.isDirectory() && e.name !== "node_modules" && !e.name.startsWith("."))
        .map((e) => e.name);
    } catch {
      return [];
    }
    if (seg === "**") {
      return [walk(base, rest), ...dirs.map((d) => walk(join(base, d), segs))].flat();
    }
    if (seg === "*") return dirs.flatMap((d) => walk(join(base, d), rest));
    return dirs.includes(seg!) ? walk(join(base, seg!), rest) : [];
  };
  return walk(root, segments);
}

/**
 * Discovers the workspace packages you manage (pnpm or npm/yarn workspaces) by
 * walking up from `start`, so `argent commons` can find dependencies shared
 * across them. Returns undefined when there's no workspace configuration.
 */
export function findWorkspaceManifests(
  start: string,
  includeDev: boolean,
): { root: string; manifests: CommonsManifest[] } | undefined {
  let dir = start;
  const fsRoot = parse(dir).root;
  let root: string | undefined;
  let globs: string[] = [];

  while (true) {
    const pnpmYaml = join(dir, "pnpm-workspace.yaml");
    if (existsSync(pnpmYaml)) {
      globs = pnpmGlobs(readFileSync(pnpmYaml, "utf8"));
      root = dir;
      break;
    }
    const pkg = readPkg(join(dir, "package.json"));
    const ws = pkg?.workspaces;
    if (Array.isArray(ws)) {
      globs = ws as string[];
      root = dir;
      break;
    } else if (ws && typeof ws === "object" && Array.isArray((ws as { packages?: unknown }).packages)) {
      globs = (ws as { packages: string[] }).packages;
      root = dir;
      break;
    }
    if (dir === fsRoot) return undefined;
    dir = dirname(dir);
  }

  const seen = new Set<string>();
  const manifests: CommonsManifest[] = [];
  for (const glob of globs) {
    if (glob.startsWith("!")) continue; // negations not supported
    for (const memberDir of expandGlob(root, glob)) {
      const path = join(memberDir, "package.json");
      if (seen.has(path) || !existsSync(path)) continue;
      seen.add(path);
      const loaded = loadManifest(path, includeDev);
      if (loaded.entries.length) {
        manifests.push({ name: loaded.name, entries: loaded.entries });
      }
    }
  }
  return { root, manifests };
}
