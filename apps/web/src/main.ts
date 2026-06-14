import {
  availableProviders,
  evaluatePackage,
  type ProviderResult,
  type RiskLevel,
  type RiskReport,
} from "@argent/core";
import "./style.css";

const form = document.querySelector<HTMLFormElement>("#form")!;
const input = document.querySelector<HTMLInputElement>("#pkg")!;
const submit = document.querySelector<HTMLButtonElement>("#submit")!;
const result = document.querySelector<HTMLElement>("#result")!;
const sources = document.querySelector<HTMLParagraphElement>("#sources")!;

sources.textContent = `In the browser we query: ${availableProviders(true).join(", ")}. socket.dev & Snyk Advisor require the CLI.`;

function parseSpec(raw: string): { name: string; version?: string } {
  const input = raw.trim();
  const at = input.lastIndexOf("@");
  if (at <= 0) return { name: input };
  return { name: input.slice(0, at), version: input.slice(at + 1) };
}

const escape = (s: string) =>
  s.replace(/[&<>"]/g, (c) =>
    c === "&" ? "&amp;" : c === "<" ? "&lt;" : c === ">" ? "&gt;" : "&quot;",
  );

function badge(level: RiskLevel): string {
  return `<span class="badge ${level}">${level.toUpperCase()}</span>`;
}

// Build-vs-buy verdict labels — an adoption axis, not a security severity.
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
    </div>`;
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const { name, version } = parseSpec(input.value);
  if (!name) return;

  submit.disabled = true;
  submit.textContent = "Checking…";
  result.innerHTML = `<p class="loading">Querying ${escape(name)}…</p>`;

  try {
    const report = await evaluatePackage(name, { version, browser: true });
    result.innerHTML = renderReport(report);
    // Reflect the checked package in the URL so results are shareable.
    const url = new URL(window.location.href);
    url.searchParams.set("pkg", input.value.trim());
    window.history.replaceState({}, "", url);
  } catch (err) {
    result.innerHTML = `<p class="error-box">Failed: ${escape(
      err instanceof Error ? err.message : String(err),
    )}</p>`;
  } finally {
    submit.disabled = false;
    submit.textContent = "Check";
  }
});

// Allow deep-linking: ?pkg=express auto-runs the check.
const preset = new URL(window.location.href).searchParams.get("pkg");
if (preset) {
  input.value = preset;
  form.requestSubmit();
}
