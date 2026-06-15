import { getJson } from "./http.js";

export const REGISTRY = "https://registry.npmjs.org";

export interface RegistryDoc {
  description?: string;
  keywords?: string[];
  license?: string | { type?: string };
  maintainers?: { name?: string }[];
  versions: Record<
    string,
    {
      dependencies?: Record<string, string>;
      keywords?: string[];
      scripts?: Record<string, string>;
      deprecated?: string;
      license?: string | { type?: string };
      dist?: {
        unpackedSize?: number;
        fileCount?: number;
        attestations?: { provenance?: unknown };
      };
    }
  >;
}

/** npm registry client with a per-run document cache (dedupes lookups). */
export interface RegistryClient {
  doc(name: string): Promise<RegistryDoc | undefined>;
  size(name: string, version: string): Promise<number | undefined>;
}

export function makeRegistry(fetchImpl: typeof fetch): RegistryClient {
  const cache = new Map<string, Promise<RegistryDoc | undefined>>();
  const doc = (name: string): Promise<RegistryDoc | undefined> => {
    let p = cache.get(name);
    if (!p) {
      p = getJson<RegistryDoc>(`${REGISTRY}/${encodeURIComponent(name)}`, {
        fetch: fetchImpl,
      }).catch(() => undefined);
      cache.set(name, p);
    }
    return p;
  };
  const size = async (name: string, version: string): Promise<number | undefined> =>
    (await doc(name))?.versions?.[version]?.dist?.unpackedSize;
  return { doc, size };
}

/** Runs `fn` over items with bounded concurrency, preserving order. */
async function mapLimit<T, R>(
  items: T[],
  limit: number,
  fn: (item: T) => Promise<R>,
): Promise<R[]> {
  const out = new Array<R>(items.length);
  let cursor = 0;
  const workers = Array.from(
    { length: Math.max(1, Math.min(limit, items.length)) },
    async () => {
      while (true) {
        const i = cursor++;
        if (i >= items.length) break;
        out[i] = await fn(items[i]!);
      }
    },
  );
  await Promise.all(workers);
  return out;
}

export interface Footprint {
  /** undefined when NO size was known (don't report a misleading 0 B). */
  bytes: number | undefined;
  /** false when at least one size was unknown, so a known `bytes` is a floor. */
  complete: boolean;
}

/**
 * Sums unpacked sizes. Older packages predate npm's `dist.unpackedSize`, so a
 * size can be missing: `bytes` is the sum of the known ones, `undefined` if none
 * were known at all (so callers show "?" rather than "0 B"), and `complete` is
 * false whenever any were missing.
 */
export function sumSizes(sizes: (number | undefined)[]): Footprint {
  // No packages to sum is a definite 0 (e.g. a fully-shared dep sheds nothing
  // uniquely) — distinct from "we looked but every size was unknown".
  if (sizes.length === 0) return { bytes: 0, complete: true };
  let total = 0;
  let known = 0;
  let missing = 0;
  for (const s of sizes) {
    if (typeof s === "number") {
      total += s;
      known++;
    } else missing++;
  }
  return { bytes: known > 0 ? total : undefined, complete: missing === 0 };
}

/**
 * Sums the unpacked sizes of a set of packages (the install footprint).
 * The shared registry cache means repeated packages are fetched once.
 */
export async function footprintOf(
  keys: { name: string; version: string }[],
  registry: RegistryClient,
): Promise<Footprint> {
  const sizes = await mapLimit(keys, 10, (k) => registry.size(k.name, k.version));
  return sumSizes(sizes);
}
