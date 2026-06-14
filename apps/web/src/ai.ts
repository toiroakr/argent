// Minimal ambient typing for Chrome's built-in Prompt API (`LanguageModel`),
// which isn't part of the standard TS DOM lib yet.
interface LanguageModelSession {
  prompt(input: string, opts?: { signal?: AbortSignal }): Promise<string>;
  destroy(): void;
}
interface LanguageModelStatic {
  availability(opts?: unknown): Promise<string>;
  create(opts?: {
    initialPrompts?: { role: string; content: string }[];
    monitor?: (m: EventTarget) => void;
    signal?: AbortSignal;
  }): Promise<LanguageModelSession>;
}
declare const LanguageModel: LanguageModelStatic | undefined;

export type AiStatus = "unavailable" | "downloadable" | "downloading" | "available";

/** True when the browser exposes the built-in Prompt API at all. */
export function aiSupported(): boolean {
  return typeof LanguageModel !== "undefined";
}

/** Normalizes the various availability strings Chrome has shipped over time. */
export async function aiStatus(): Promise<AiStatus> {
  if (typeof LanguageModel === "undefined") return "unavailable";
  try {
    const a = await LanguageModel.availability();
    if (a === "available" || a === "readily") return "available";
    if (a === "downloadable" || a === "after-download") return "downloadable";
    if (a === "downloading") return "downloading";
    return "unavailable";
  } catch {
    return "unavailable";
  }
}

const SYSTEM = `You are a supply-chain assistant inside the "argent" tool. You are
given a machine-generated risk report (or dependency audit) for an npm package.
Write a short, plain-language interpretation (3-5 sentences) and end with a clear
bottom line: Adopt / Adopt with care / Avoid / Consider reimplementing. Base
everything ONLY on the data provided — never invent versions, scores, or
advisories. Be concise and practical.`;

/**
 * Runs the report summary through the on-device model and returns its text.
 * Throws if the API is unavailable.
 */
export async function interpret(
  summary: string,
  onProgress?: (loaded: number) => void,
  signal?: AbortSignal,
): Promise<string> {
  if (typeof LanguageModel === "undefined") {
    throw new Error("Built-in AI is not available in this browser");
  }
  const session = await LanguageModel.create({
    initialPrompts: [{ role: "system", content: SYSTEM }],
    monitor(m) {
      m.addEventListener("downloadprogress", (e: Event) => {
        onProgress?.((e as ProgressEvent).loaded);
      });
    },
    signal,
  });
  try {
    const out = await session.prompt(summary, { signal });
    return out.trim();
  } finally {
    session.destroy();
  }
}
