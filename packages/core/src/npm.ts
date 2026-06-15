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

/**
 * Sums the unpacked sizes of a set of packages (the install footprint).
 * `complete` is false when some sizes were unknown, so `bytes` is a floor.
 * The shared registry cache means repeated packages are fetched once.
 */
export async function footprintOf(
  keys: { name: string; version: string }[],
  registry: RegistryClient,
): Promise<{ bytes: number; complete: boolean }> {
  const sizes = await mapLimit(keys, 10, (k) => registry.size(k.name, k.version));
  let bytes = 0;
  let complete = true;
  for (const s of sizes) {
    if (typeof s === "number") bytes += s;
    else complete = false;
  }
  return { bytes, complete };
}
