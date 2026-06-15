import {
  auditDependencies,
  availableProviders,
  evaluatePackage,
  type AuditReport,
  type DepAudit,
  type ProviderResult,
  type RiskLevel,
  type RiskReport,
} from "@argent/core";
import { aiStatus, aiSupported, interpret } from "./ai.js";
import "./style.css";

type Mode = "check" | "audit";

const form = document.querySelector<HTMLFormElement>("#form")!;
const input = document.querySelector<HTMLInputElement>("#pkg")!;
const submit = document.querySelector<HTMLButtonElement>("#submit")!;
const result = document.querySelector<HTMLElement>("#result")!;
const sources = document.querySelector<HTMLParagraphElement>("#sources")!;
const tabs = [...document.querySelectorAll<HTMLButtonElement>(".tab")];

let mode: Mode = "check";

// ---------------------------------------------------------------- shared utils

function parseSpec(raw: string): { name: string; version?: string } {
  const s = raw.trim();
  const at = s.lastIndexOf("@");
  if (at <= 0) return { name: s };
  return { name: s.slice(0, at), version: s.slice(at + 1) };
}

const escape = (s: string) =>
  s.replace(/[&<>"]/g, (c) =>
    c === "&" ? "&amp;" : c === "<" ? "&lt;" : c === ">" ? "&gt;" : "&quot;",
  );

function badge(level: RiskLevel): string {
  return `<span class="badge ${level}">${level.toUpperCase()}</span>`;
}

function humanBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

// ------------------------------------------------------------------ check mode

const ADVISORY_TAG: Record<RiskLevel, string> = {
  high: "REIMPLEMENT?",
  medium: "CONSIDER",
  low: "KEEP",
  critical: "KEEP",
  unknown: "N/A",
};

function renderProvider(r: ProviderResult): string {
  const isAdvisory = r.advisory && r.ok;
  const score = isAdvisory
    ? `<span class="advisory-tag">💡 ${ADVISORY_TAG[r.level]}</span>`
    : r.score !== undefined
      ? `<span class="score">${r.score}/100</span>`
      : "";
  const cls = isAdvisory ? "advisory" : r.skipped ? "skipped" : r.ok ? r.level : "error";
  const findings = r.findings
    .map(
      (f) =>
        `<li><span class="f-label">${escape(f.label)}</span><span class="f-value">${escape(f.value)}${
          f.level && f.level !== "unknown" ? " " + badge(f.level) : ""
        }</span></li>`,
    )
    .join("");
  const link = r.url
    ? `<a class="provider-link" href="${escape(r.url)}" target="_blank" rel="noopener">view →</a>`
    : "";
  return `
    <article class="provider ${cls}">
      <div class="provider-head">
        <h3>${escape(r.provider)}</h3>
        ${score}
        ${isAdvisory ? "" : badge(r.ok ? r.level : "unknown")}
      </div>
      <p class="provider-summary">${escape(r.summary)}${r.error ? ` — <span class="err">${escape(r.error)}</span>` : ""}</p>
      ${findings ? `<ul class="findings">${findings}</ul>` : ""}
      ${link}
    </article>`;
}

function renderReport(report: RiskReport): string {
  const { package: pkg } = report;
  return `
    <div class="report">
      <div class="report-head">
        <h2>${escape(pkg.name)}<span class="ver">@${escape(pkg.version)}</span></h2>
        ${badge(report.overall)}
      </div>
      ${pkg.repoUrl ? `<p class="repo">${escape(pkg.repoUrl)}</p>` : ""}
      <div class="providers">${report.results.map(renderProvider).join("")}</div>
      ${aiPanelHtml()}
    </div>`;
}

function summarizeReport(report: RiskReport): string {
  const lines = [
    `Package: ${report.package.name}@${report.package.version}`,
    `Overall security risk: ${report.overall}`,
  ];
  for (const r of report.results) {
    if (r.skipped) continue;
    const score = r.score !== undefined ? ` [${r.score}/100]` : "";
    lines.push(`- ${r.provider}${score}: ${r.summary}`);
    for (const f of r.findings) lines.push(`    ${f.label}: ${f.value}`);
  }
  return lines.join("\n");
}

// ------------------------------------------------------------------ audit mode

function depRow(d: DepAudit): string {
  const tag = d.direct ? "" : " ·";
  const size =
    d.footprintBytes !== undefined
      ? humanBytes(d.footprintBytes) + (d.footprintApprox ? "+" : "")
      : "?";
  const risk =
    d.advisoryCount === 0
      ? `<span class="dim">clean</span>`
      : `${badge(d.severity)}<span class="dim">×${d.advisoryCount}</span>`;
  const drop =
    d.dropScore >= 70 ? "hi" : d.dropScore >= 45 ? "mid" : d.dropScore >= 25 ? "lo" : "min";
  return `
    <tr>
      <td class="drop ${drop}">${d.dropScore}</td>
      <td class="dep">${escape(d.name)}<span class="dim">@${escape(d.version)}${tag}</span></td>
      <td class="size">${size}</td>
      <td class="risk">${risk}</td>
      <td class="verdict ${d.verdict}">${d.verdict}</td>
      <td class="why dim">${escape(d.reasons[0] ?? "")}</td>
    </tr>`;
}

function auditTable(deps: DepAudit[], caption?: string): string {
  if (deps.length === 0) return "";
  const shown = deps.slice(0, 40);
  const more =
    deps.length > shown.length
      ? `<p class="repo">… and ${deps.length - shown.length} more</p>`
      : "";
  return `
    ${caption ? `<h3 class="audit-caption">${caption}</h3>` : ""}
    <table class="audit">
      <thead><tr><th>drop</th><th>package</th><th>size↓</th><th>risk</th><th>action</th><th>why</th></tr></thead>
      <tbody>${shown.map(depRow).join("")}</tbody>
    </table>
    ${more}`;
}

function renderAudit(report: AuditReport): string {
  const { target } = report;
  if (report.ranking.length === 0) {
    return `<div class="report"><div class="report-head"><h2>${escape(target.name)}<span class="ver">@${escape(target.version)}</span></h2></div>
      <p class="repo">No dependencies — nothing to drop. 🎉</p></div>`;
  }
  const capped =
    report.evaluated < report.totalDependencies
      ? ` (evaluated ${report.evaluated}, capped)`
      : "";
  const prod = report.ranking.filter((d) => !d.dev);
  const dev = report.ranking.filter((d) => d.dev);
  const tables =
    dev.length && prod.length
      ? auditTable(prod, "dependencies") + auditTable(dev, "devDependencies")
      : auditTable(report.ranking);
  return `
    <div class="report">
      <div class="report-head">
        <h2>${escape(target.name)}<span class="ver">@${escape(target.version)}</span></h2>
      </div>
      <p class="repo">${report.totalDependencies} dependencies${capped}. <code>drop</code> = how cheaply you can escape it (small + self-contained scores high; a big dep subtree lowers it). Deps with known advisories are a separate axis, listed first. <code>size↓</code> = install size incl. deps. · = transitive.</p>
      ${tables}
      ${aiPanelHtml()}
    </div>`;
}

function summarizeAudit(report: AuditReport): string {
  const lines = [
    `Dependency audit of ${report.target.name}@${report.target.version} — ${report.totalDependencies} dependencies.`,
    `dropScore is an adoption signal (how inline-able + how much install weight it sheds); higher = more worth escaping. Known advisories are a separate, urgent axis (call those out first).`,
  ];
  for (const d of report.ranking.slice(0, 12)) {
    const risk = d.advisoryCount === 0 ? "clean" : `${d.severity} (${d.advisoryCount} advisory)`;
    const size = d.footprintBytes !== undefined ? humanBytes(d.footprintBytes) : "?";
    lines.push(
      `- ${d.name}@${d.version}: drop ${d.dropScore}, risk ${risk}, action ${d.verdict}, install size ${size}`,
    );
  }
  return lines.join("\n");
}

// -------------------------------------------------------------------- AI panel

function aiPanelHtml(): string {
  return `
    <section class="ai-panel" id="ai-panel">
      <div class="ai-head">
        <span class="ai-title">✨ AI interpretation</span>
        <span class="ai-sub">on-device · experimental</span>
      </div>
      <div class="ai-body" id="ai-body"></div>
    </section>`;
}

let currentSummary = "";

async function mountAiPanel(summary: string): Promise<void> {
  currentSummary = summary;
  const body = document.querySelector<HTMLElement>("#ai-body");
  if (!body) return;

  if (!aiSupported()) {
    body.innerHTML = `<p class="ai-note">On-device AI isn't available in this browser. It needs Chrome with the built-in Prompt API (see <a href="https://developer.chrome.com/docs/ai/built-in-apis" target="_blank" rel="noopener">Chrome built-in AI</a>).</p>`;
    return;
  }
  const status = await aiStatus();
  if (status === "unavailable") {
    body.innerHTML = `<p class="ai-note">Your browser exposes the Prompt API but the on-device model isn't available right now.</p>`;
    return;
  }
  const hint =
    status === "downloadable"
      ? " The model (~couple of GB) downloads on first use."
      : status === "downloading"
        ? " The model is still downloading…"
        : "";
  body.innerHTML = `
    <button type="button" class="ai-btn" id="ai-btn">Interpret with on-device AI</button>
    <p class="ai-note">A summary of the results above is sent to your browser's built-in model. Nothing leaves your device.${hint}</p>`;
  document.querySelector<HTMLButtonElement>("#ai-btn")?.addEventListener("click", runInterpret);
}

async function runInterpret(): Promise<void> {
  const body = document.querySelector<HTMLElement>("#ai-body");
  const btn = document.querySelector<HTMLButtonElement>("#ai-btn");
  if (!body || !btn) return;
  btn.disabled = true;
  btn.textContent = "Thinking…";
  body.querySelector(".ai-note")?.remove();
  const progress = document.createElement("p");
  progress.className = "ai-note";
  body.appendChild(progress);

  try {
    const text = await interpret(currentSummary, (loaded) => {
      progress.textContent = `Downloading model… ${Math.round(loaded * 100)}%`;
    });
    progress.remove();
    const paras = text
      .split(/\n+/)
      .filter(Boolean)
      .map((p) => `<p>${escape(p)}</p>`)
      .join("");
    body.innerHTML = `
      <div class="ai-output">${paras}</div>
      <p class="ai-disclaimer">⚠️ Generated by your browser's on-device AI — it can be wrong. Verify against the data above.</p>`;
  } catch (err) {
    progress.remove();
    btn.disabled = false;
    btn.textContent = "Interpret with on-device AI";
    const note = document.createElement("p");
    note.className = "ai-note err";
    note.textContent = `AI interpretation failed: ${err instanceof Error ? err.message : String(err)}`;
    body.appendChild(note);
  }
}

// ----------------------------------------------------------------------- modes

function setMode(next: Mode): void {
  mode = next;
  for (const t of tabs) t.classList.toggle("active", t.dataset.mode === next);
  input.placeholder =
    next === "check"
      ? "package name, e.g. express or @scope/pkg@1.0.0"
      : "package to audit, e.g. express";
  submit.textContent = next === "check" ? "Check" : "Audit";
  sources.textContent =
    next === "check"
      ? `In the browser we query: ${availableProviders(true).join(", ")}. socket.dev & Snyk Advisor require the CLI.`
      : "Audits the package's full resolved dependency graph (deps.dev + npm registry) and ranks which deps are worth dropping.";
}

for (const t of tabs) {
  t.addEventListener("click", () => {
    setMode(t.dataset.mode as Mode);
    syncUrl();
  });
}

function syncUrl(): void {
  const url = new URL(window.location.href);
  url.searchParams.set("mode", mode);
  if (input.value.trim()) url.searchParams.set("pkg", input.value.trim());
  window.history.replaceState({}, "", url);
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const { name, version } = parseSpec(input.value);
  if (!name) return;

  submit.disabled = true;
  submit.textContent = mode === "check" ? "Checking…" : "Auditing…";
  result.innerHTML = `<p class="loading">${mode === "check" ? "Querying" : "Auditing"} ${escape(name)}…</p>`;

  try {
    let summary = "";
    if (mode === "check") {
      const report = await evaluatePackage(name, { version, browser: true });
      result.innerHTML = renderReport(report);
      summary = summarizeReport(report);
    } else {
      const report = await auditDependencies(name, { version });
      result.innerHTML = renderAudit(report);
      summary = summarizeAudit(report);
    }
    syncUrl();
    void mountAiPanel(summary);
  } catch (err) {
    result.innerHTML = `<p class="error-box">Failed: ${escape(
      err instanceof Error ? err.message : String(err),
    )}</p>`;
  } finally {
    submit.disabled = false;
    submit.textContent = mode === "check" ? "Check" : "Audit";
  }
});

// Deep-linking: ?mode=audit&pkg=express auto-runs.
const params = new URL(window.location.href).searchParams;
setMode(params.get("mode") === "audit" ? "audit" : "check");
const preset = params.get("pkg");
if (preset) {
  input.value = preset;
  form.requestSubmit();
}
