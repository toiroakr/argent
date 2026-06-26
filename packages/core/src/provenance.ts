import { getJson } from "./http.js";
import { REGISTRY } from "./npm.js";

/**
 * Trust in the link between a package and the source repository its metadata
 * points at:
 *   - verified   — npm provenance attests it was built from that exact repo
 *   - unverified — no usable provenance (the common case: most packages publish
 *                  none), so the link can't be confirmed either way
 *   - mismatch   — provenance attests a DIFFERENT repo than the one linked: a
 *                  package pointing its metadata at an unrelated healthy repo to
 *                  inherit its reputation (Scorecard / Actions / Community)
 */
export type RepoTrust = "verified" | "unverified" | "mismatch";

export interface RepoVerification {
  trust: RepoTrust;
  /** The repo the provenance was actually built from, when decoded. */
  attestedRepo?: string;
}

interface AttestationBundle {
  attestations?: {
    predicateType?: string;
    bundle?: { dsseEnvelope?: { payload?: string } };
  }[];
}

/** Normalizes a repo URL/id to bare `host/org/repo`, lowercased, no `.git`. */
export function normalizeRepo(raw: string | undefined): string | undefined {
  if (!raw) return undefined;
  const m = raw
    .replace(/^git\+/, "")
    .match(/(github\.com|gitlab\.com|bitbucket\.org)[/:]([^/]+)\/([^/#?]+)/i);
  if (!m) return undefined;
  return `${m[1]!.toLowerCase()}/${m[2]}/${m[3]!.replace(/\.git$/, "")}`;
}

/**
 * Pulls a source-repo URL out of a decoded SLSA provenance statement. The shape
 * varies across builders/versions, so several known locations are tried.
 */
export function repoFromStatement(stmt: unknown): string | undefined {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const p = stmt as any;
  const deps = p?.predicate?.buildDefinition?.resolvedDependencies;
  const candidates: unknown[] = [
    p?.predicate?.buildDefinition?.externalParameters?.workflow?.repository,
    p?.predicate?.invocation?.configSource?.uri,
    ...(Array.isArray(deps) ? deps.map((d: { uri?: unknown }) => d?.uri) : []),
  ];
  for (const c of candidates) {
    if (typeof c === "string") {
      const n = normalizeRepo(c);
      if (n) return n;
    }
  }
  return undefined;
}

/** Base64 decode that works in both Node and the browser. */
function decodeBase64(b64: string): string {
  if (typeof globalThis.atob === "function") return globalThis.atob(b64);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return (globalThis as any).Buffer.from(b64, "base64").toString("utf8");
}

/**
 * Verifies that the repo a package *links to* is the one its npm provenance
 * attestation was actually built from — guarding against a package pointing its
 * metadata at an unrelated, reputable repo to borrow its security scores.
 *
 * Best-effort and fail-open: any lookup/parse error yields "unverified" (also
 * the expected result for the many packages that publish no provenance). Only a
 * positively decoded, differing repo returns "mismatch".
 */
export async function verifyRepo(
  name: string,
  version: string,
  linkedRepo: string | undefined,
  fetchImpl: typeof fetch,
): Promise<RepoVerification> {
  const linked = normalizeRepo(linkedRepo);
  let data: AttestationBundle;
  try {
    data = await getJson<AttestationBundle>(
      `${REGISTRY}/-/npm/v1/attestations/${encodeURIComponent(`${name}@${version}`)}`,
      { fetch: fetchImpl },
    );
  } catch {
    return { trust: "unverified" };
  }

  for (const att of data.attestations ?? []) {
    const payload = att.bundle?.dsseEnvelope?.payload;
    if (!payload) continue;
    let attested: string | undefined;
    try {
      attested = repoFromStatement(JSON.parse(decodeBase64(payload)));
    } catch {
      continue;
    }
    if (!attested) continue;
    if (linked) {
      return linked === attested
        ? { trust: "verified", attestedRepo: attested }
        : { trust: "mismatch", attestedRepo: attested };
    }
    // No linked repo to compare against (repo-based providers were skipped
    // anyway): record what we found, but we can't "verify" a link that's absent.
    return { trust: "unverified", attestedRepo: attested };
  }
  return { trust: "unverified" };
}
