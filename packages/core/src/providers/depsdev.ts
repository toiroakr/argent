import { getJson, HttpError } from "../http.js";
import { levelFromAdvisories, levelFromSeverity } from "../risk.js";
import type { EvalContext, ProviderFinding, ProviderResult } from "../types.js";

const BASE = "https://api.deps.dev/v3";

interface DepsDevPackage {
  versions?: { versionKey: { version: string }; isDefault?: boolean }[];
}

interface DepsDevVersion {
  versionKey?: { version: string };
  licenses?: string[];
  advisoryKeys?: { id: string }[];
  links?: { label: string; url: string }[];
  relatedProjects?: {
    projectKey?: { id: string };
    relationType?: string;
  }[];
}

interface DepsDevAdvisory {
  title?: string;
  aliases?: string[];
  severity?: string;
}

export interface ResolvedPackage {
  version: string;
  /** `host/org/repo` extracted from related projects or links, if any. */
  repoUrl?: string;
  result: ProviderResult;
}

function pickRepo(version: DepsDevVersion): string | undefined {
  const fromProject = version.relatedProjects?.find((p) =>
    /^github\.com\/|^gitlab\.com\/|^bitbucket\.org\//.test(p.projectKey?.id ?? ""),
  )?.projectKey?.id;
  if (fromProject) return fromProject;

  const link = version.links?.find((l) =>
    /github\.com|gitlab\.com|bitbucket\.org/.test(l.url),
  )?.url;
  if (!link) return undefined;
  const m = link.match(/(github\.com|gitlab\.com|bitbucket\.org)\/([^/]+)\/([^/#?]+)/);
  if (!m) return undefined;
  return `${m[1]}/${m[2]}/${m[3]!.replace(/\.git$/, "")}`;
}

async function resolveVersion(
  name: string,
  requested: string | undefined,
  ctx: Pick<EvalContext, "fetch">,
): Promise<string> {
  if (requested) return requested;
  const pkg = await getJson<DepsDevPackage>(
    `${BASE}/systems/npm/packages/${encodeURIComponent(name)}`,
    { fetch: ctx.fetch },
  );
  const versions = pkg.versions ?? [];
  const def = versions.find((v) => v.isDefault) ?? versions.at(-1);
  if (!def) throw new Error(`No versions found for ${name}`);
  return def.versionKey.version;
}

/**
 * Queries deps.dev for the package version, its declared licenses and any
 * known security advisories. Doubles as the resolution step that other
 * providers depend on (version + source repo).
 */
export async function evaluateDepsDev(
  name: string,
  requestedVersion: string | undefined,
  ctx: Pick<EvalContext, "fetch">,
): Promise<ResolvedPackage> {
  const url = `https://deps.dev/npm/${encodeURIComponent(name)}`;
  try {
    const version = await resolveVersion(name, requestedVersion, ctx);
    const ver = await getJson<DepsDevVersion>(
      `${BASE}/systems/npm/packages/${encodeURIComponent(name)}/versions/${encodeURIComponent(version)}`,
      { fetch: ctx.fetch },
    );

    const repoUrl = pickRepo(ver);
    const findings: ProviderFinding[] = [];

    const licenses = ver.licenses ?? [];
    findings.push({
      label: "Licenses",
      value: licenses.length ? licenses.join(", ") : "none declared",
      level: licenses.length ? "low" : "medium",
    });

    const advisoryKeys = ver.advisoryKeys ?? [];
    const advisories = await Promise.all(
      advisoryKeys.map((a) =>
        getJson<DepsDevAdvisory>(`${BASE}/advisories/${encodeURIComponent(a.id)}`, {
          fetch: ctx.fetch,
        }).catch(() => ({ title: a.id }) as DepsDevAdvisory),
      ),
    );

    const advLevels = advisories.map((a) => levelFromSeverity(a.severity));
    for (const [i, a] of advisories.entries()) {
      findings.push({
        label: a.aliases?.[0] ?? advisoryKeys[i]?.id ?? "advisory",
        value: a.title ?? "(no title)",
        level: advLevels[i] ?? "unknown",
      });
    }

    // A known advisory whose severity we can't parse still counts: see
    // levelFromAdvisories (floors all-unknown advisories to "medium").
    const level = levelFromAdvisories(advLevels);
    const summary = advisories.length
      ? `${advisories.length} known advisory(ies) for ${version}`
      : `No known advisories for ${version}`;

    return {
      version,
      repoUrl,
      result: {
        provider: "deps.dev",
        ok: true,
        level,
        summary,
        findings,
        url: `${url}/v/${encodeURIComponent(version)}`,
      },
    };
  } catch (err) {
    const message =
      err instanceof HttpError && err.status === 404
        ? "Package not found on deps.dev"
        : err instanceof Error
          ? err.message
          : String(err);
    return {
      version: requestedVersion ?? "unknown",
      result: {
        provider: "deps.dev",
        ok: false,
        level: "unknown",
        summary: "deps.dev lookup failed",
        findings: [],
        url,
        error: message,
      },
    };
  }
}
