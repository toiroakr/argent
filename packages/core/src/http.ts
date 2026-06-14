/** Thrown when a fetch returns a non-2xx status so callers can branch on it. */
export class HttpError extends Error {
  constructor(
    public status: number,
    public url: string,
  ) {
    super(`HTTP ${status} for ${url}`);
    this.name = "HttpError";
  }
}

export interface FetchOptions {
  fetch: typeof fetch;
  timeoutMs?: number;
  headers?: Record<string, string>;
}

async function withTimeout(
  fetchImpl: typeof fetch,
  url: string,
  init: RequestInit,
  timeoutMs: number,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetchImpl(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

export async function getJson<T>(url: string, opts: FetchOptions): Promise<T> {
  const res = await withTimeout(
    opts.fetch,
    url,
    { headers: { accept: "application/json", ...opts.headers } },
    opts.timeoutMs ?? 10_000,
  );
  if (!res.ok) throw new HttpError(res.status, url);
  return (await res.json()) as T;
}

export async function getText(url: string, opts: FetchOptions): Promise<string> {
  const res = await withTimeout(
    opts.fetch,
    url,
    { headers: opts.headers ?? {} },
    opts.timeoutMs ?? 10_000,
  );
  if (!res.ok) throw new HttpError(res.status, url);
  return await res.text();
}

/** POSTs a JSON body and returns the raw response text (e.g. JSON or NDJSON). */
export async function postText(
  url: string,
  body: string,
  opts: FetchOptions,
): Promise<string> {
  const res = await withTimeout(
    opts.fetch,
    url,
    {
      method: "POST",
      headers: { "content-type": "application/json", ...opts.headers },
      body,
    },
    opts.timeoutMs ?? 10_000,
  );
  if (!res.ok) throw new HttpError(res.status, url);
  return await res.text();
}
