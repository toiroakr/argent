# 🛡️ argent

**Assess the risk of an npm package _before_ you install it.**

`argent` aggregates supply-chain risk signals from multiple sources into a
single, normalized report so you can make an informed call before adding a
dependency.

> **Why "argent"?** _Argent_ is the heraldic/French word for **silver**. In
> European courts, and among Japanese shōguns and daimyō from the Sengoku
> through the Edo period, silver tableware and chopsticks were used to test
> food for poison before eating — sometimes alongside a dedicated taster
> (_dokumi-yaku_). `argent` is that silver spoon for your dependencies:
> check a package for "poison" *before* you ingest it.

| Source | What it tells you | CLI | Web |
| --- | --- | :-: | :-: |
| [deps.dev](https://deps.dev) | Known security advisories, declared licenses, source repo | ✅ | ✅ |
| [OpenSSF Scorecard](https://securityscorecards.dev) | Heuristic security health of the source repo | ✅ | ✅ |
| [socket.dev](https://socket.dev) | Supply-chain risk from static analysis | ✅¹ | 🔗² |
| [Snyk Advisor](https://snyk.io/advisor) | Package health score (security/popularity/maintenance/community) | ✅³ | 🔗² |

> ¹ Requires a `SOCKET_API_KEY`. ² Needs a server/CLI (API key or CORS), so the
> web app links out instead. ³ Scraped from the public Advisor page (best-effort).

Results are normalized to a shared scale — `low` · `medium` · `high` ·
`critical` · `unknown` — and the report's overall level is the worst across all
sources that returned data.

## Two ways to use it

### CLI

> ℹ️ Published as the scoped package **`@toiroakr/argent`** (the bare `argent`
> name on npm belongs to an unrelated project). The installed command is still
> `argent`.

```bash
# one-off, no install
npx @toiroakr/argent express

# or install the `argent` command globally
npm i -g @toiroakr/argent
argent express

# pin a version, check several at once
npx @toiroakr/argent left-pad@1.3.0 lodash @sindresorhus/is

# CI gate: non-zero exit when risk >= high
npx @toiroakr/argent chalk --fail-on high

# machine-readable
npx @toiroakr/argent express --json

# enable socket.dev
SOCKET_API_KEY=sk_... npx @toiroakr/argent express
```

Options: `--json`, `--fail-on <low|medium|high|critical>`,
`--socket-key <token>`, `-h/--help`.

### Web (GitHub Pages)

A static, browser-only form: <https://toiroakr.github.io/argent/>

It runs the CORS-safe sources (deps.dev + OpenSSF Scorecard) directly in your
browser — no backend, nothing logged. Deep-link a package with
`?pkg=express`. socket.dev and Snyk Advisor are linked out since they can't be
called safely from the browser.

## Repository layout

```
packages/core   @argent/core       — provider logic + normalization (private, bundled into the CLI)
packages/cli    @toiroakr/argent   — the CLI (the package published to npm)
apps/web        @argent/web        — the GitHub Pages form (Vite)
```

The CLI and the web app share the exact same evaluation logic in
`@argent/core`; each provider declares whether it is `browserSafe`, and the web
build simply skips the ones that aren't.

## Development

```bash
pnpm install
pnpm test         # unit tests (vitest)
pnpm typecheck
pnpm build        # build core + cli
pnpm dev:web      # run the web app locally (Vite dev server)
pnpm build:web    # build the static site into apps/web/dist
```

Run the CLI from source:

```bash
pnpm cli express --json
```

## How the score is derived

- Provider scores are normalized to **0–100, higher = safer**.
  - OpenSSF Scorecard `x/10` → `x*10`.
  - socket.dev category scores `0..1` → averaged → `*100`.
  - Snyk Advisor health score is already `/100`.
- A score maps to a level: `≥80 low`, `≥60 medium`, `≥40 high`, else `critical`.
- Advisory severities (`CRITICAL/HIGH/MEDIUM/LOW`) map directly.
- The package's **overall** level is the worst real level across providers;
  `unknown` never raises the overall on its own.

> ⚠️ `argent` is a decision aid, not a guarantee. A clean report means "no
> signal from these sources", not "safe". Treat results as one input alongside
> review and judgment.

## License

MIT © toiroakr
