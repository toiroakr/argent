# @toiroakr/argent

**Assess the risk of an npm package _before_ you install it** — aggregating
[deps.dev](https://deps.dev), [OpenSSF Scorecard](https://securityscorecards.dev),
[socket.dev](https://socket.dev) and [Snyk Advisor](https://snyk.io/advisor)
into one normalized report.

> The published package is scoped (`@toiroakr/argent`) because the bare `argent`
> name on npm belongs to an unrelated project. The installed command is `argent`.

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

# enable socket.dev (otherwise skipped)
SOCKET_API_KEY=sk_... npx @toiroakr/argent express
```

Options: `--json`, `--fail-on <low|medium|high|critical>`,
`--socket-key <token>`, `-h/--help`.

Risk is normalized to a shared scale — `low` · `medium` · `high` · `critical` ·
`unknown` — and a package's overall level is the worst across the sources that
returned data. `argent` is a decision aid, not a guarantee: a clean report means
"no signal from these sources", not "safe".

There is also a browser-only form at <https://toiroakr.github.io/argent/>.

See the [full README and source](https://github.com/toiroakr/argent) for how
scores are derived and how the providers differ between the CLI and the web app.

## License

MIT © toiroakr
