<div align="center">
  <h1>HookTripwire</h1>
  <p><strong>Catch dangerous AI-agent hooks before they become trusted automation.</strong></p>
  <p>Offline static security auditing for coding-agent hooks, workflow files, and shell-backed automation.</p>

  [![CI](https://github.com/mockingbird777/hooktripwire/actions/workflows/ci.yml/badge.svg)](https://github.com/mockingbird777/hooktripwire/actions/workflows/ci.yml)
  [![Pages](https://img.shields.io/badge/live-security%20lab-6ee7d8)](https://mockingbird777.github.io/hooktripwire/)
  [![Node.js 20+](https://img.shields.io/badge/node-%E2%89%A520-5FA04E)](https://nodejs.org/)
  [![License: MIT](https://img.shields.io/badge/license-MIT-7c8cff)](LICENSE)
  [![Zero runtime dependencies](https://img.shields.io/badge/runtime%20dependencies-0-48c9b0)](package.json)
</div>

AI coding tools are rapidly gaining hooks that run after edits, before commits, on notifications, and inside CI. Those hooks often sit in reviewed-looking JSON or YAML while quietly crossing the same security boundaries as executable code. HookTripwire makes those boundaries visible.

It analyzes configuration **as text and never executes a scanned command**. Everything stays on your machine: no account, no API key, no telemetry, and no model call.

> [Explore the interactive security lab](https://mockingbird777.github.io/hooktripwire/) to see risky and hardened agent configurations side by side.

## Why HookTripwire

- **Agent-aware detection.** Finds overbroad approvals, unrestricted network/filesystem grants, secret-bearing outbound requests, shell injection boundaries, mutable actions, and sensitive path writes.
- **Useful in a terminal and in CI.** Emit readable terminal output, structured JSON, Markdown, standards-valid SARIF 2.1, or a self-contained HTML report.
- **Safe by construction.** No `eval`, subprocess execution, symlink traversal, remote fetches, or runtime dependencies. Inputs are bounded and evidence is redacted.
- **Designed for gradual adoption.** Baselines capture accepted debt; a policy file controls severity, trusted actions, host allowlists, ignored paths, and file-size limits.
- **Portable.** Strict TypeScript targeting Node.js 20+, with no platform-specific shell assumptions.

## Quick start

No installation is required:

```bash
npx --yes github:mockingbird777/hooktripwire .
```

Scan the places where agent automation usually lives:

```bash
npx --yes github:mockingbird777/hooktripwire \
  .claude .cursor .github/workflows .vscode AGENTS.md
```

HookTripwire exits with `1` when it finds an unsuppressed `high` or `critical` issue, so the default command is CI-ready.

## What it detects

| Rule | Default | Signal |
|---|---:|---|
| `HG001` | high | Destructive filesystem, disk, or worktree commands |
| `HG002` | critical | Remote content piped directly to an interpreter |
| `HG003` | critical | Potential secret or sensitive-file exfiltration |
| `HG004` | high | Wildcard or unrestricted network permission |
| `HG005` | high | Variable expansion across a shell evaluation boundary |
| `HG006` | critical | Disabled approval controls or wildcard tool access |
| `HG007` | medium | Remote GitHub Actions referenced by a mutable tag or branch |
| `HG008` | high | Mutation of SSH, cloud credential, shell startup, or system paths |
| `HG009` | high | Credentials exposed through output or shell tracing |
| `HG010` | high | Downloaded artifact executed without integrity verification |
| `HG011` | medium | Mutable container image reference |
| `HG012` | high | Entire parent environment inherited or forwarded |
| `HG013` | critical | Whole-filesystem or home-directory access |
| `HG014` | high | TLS certificate verification disabled |
| `HG015` | critical | Literal credential embedded in configuration |

Rules are deliberately evidence-based. For example, an ordinary download is not treated as a remote execution pipe, a SHA-pinned action is accepted, placeholder credentials are ignored, and outbound requests to explicitly allowed hosts do not trigger the exfiltration heuristic.

## Inputs

HookTripwire recursively discovers these text formats:

- JSON and JSONC agent settings
- YAML workflows and permission files
- Markdown agent instructions such as `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, Cursor rules, and GitHub instruction files
- shell scripts (`sh`, `bash`, and `zsh`)
- TOML automation configuration
- well-known files such as `Dockerfile`, `Makefile`, settings, hooks, and workflows

This covers common shapes used by Claude Code, Cursor, VS Code, GitHub Actions, and vendor-neutral agent frameworks without depending on any one product schema. Ordinary Markdown documentation is not selected during a directory scan, but any Markdown file can still be audited when passed as an explicit target.

Symbolic links are reported and never followed. Binary files, dependencies, lockfiles, generated output, and files above the configured size limit are skipped safely. Comment-only JSONC, YAML, TOML, shell, and Markdown content is ignored while preserving exact source locations.

## Reports

```bash
# Developer-friendly terminal output
hooktripwire .claude .cursor

# Stable data for another tool
hooktripwire . --format json --output artifacts/hooktripwire.json

# Upload to GitHub code scanning
hooktripwire .github/workflows --format sarif --output hooktripwire.sarif

# Attach a single-file report to a security review
hooktripwire . --format html --output hooktripwire-report.html

# Never fail the current command, regardless of findings
hooktripwire . --fail-on none
```

Supported formats are `terminal`, `json`, `markdown`, `sarif`, and `html`. Output files are created atomically with owner-only permissions. JSON and SARIF findings are sorted by path, line, column, and rule, and each finding has a stable 24-character fingerprint. HTML reports include a restrictive Content Security Policy, and terminal, Markdown, HTML, JSON, and SARIF outputs neutralize their format-specific injection boundaries.

Exit codes:

| Code | Meaning |
|---:|---|
| `0` | No finding met the failure threshold |
| `1` | At least one finding met the threshold |
| `2` | Invalid arguments, inaccessible input, or invalid policy/baseline |

## Least-privilege policy

HookTripwire automatically loads `.hooktripwire.json`, `.hooktripwire.yml`, or `.hooktripwire.yaml` from the current directory. YAML support is intentionally limited to a safe, non-executable subset.

```yaml
allowHosts:
  - api.github.com
  - registry.npmjs.org
trustedActions:
  - actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5
ignorePaths:
  - test/fixtures/**
severity:
  HG007: high
disabledRules:
  - HG011
maxFileBytes: 1048576
```

Pass a policy explicitly when a repository maintains several security profiles:

```bash
hooktripwire . --policy security/strict-policy.yml
```

Host allowlists accept exact hosts and `*.example.com` subdomain patterns. A wildcard does not silently include the apex domain. Trusted actions can be exact `owner/repository@ref` entries or repository names.

## Baselines without hiding new risk

Adopt HookTripwire in an existing repository without fixing everything in one pull request:

```bash
hooktripwire . --write-baseline .hooktripwire-baseline.json
git add .hooktripwire-baseline.json
```

Future scans automatically load that baseline. Existing fingerprints are suppressed; new findings still fail the build. Use `--include-suppressed` during cleanup work. Baselines contain only rule fingerprints—never source snippets or secrets.

Policy and baseline files are security control-plane inputs: a policy can disable or lower a rule, and a baseline can accept an existing finding. When CI evaluates untrusted pull requests, protect these files with `CODEOWNERS`/required review or load them from a trusted base-branch checkout outside the proposed changes. Treat any policy or baseline change as a security-sensitive code change.

## GitHub Actions

```yaml
name: Agent hook security
on: [push, pull_request]

permissions:
  contents: read

jobs:
  hooktripwire:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
      - uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4
        with:
          node-version: 20
      - run: npx --yes github:mockingbird777/hooktripwire .claude .cursor .github/workflows
```

For GitHub code scanning, generate SARIF and upload it with your organization’s approved, SHA-pinned SARIF workflow.

## Library API

The engine and formatters are also exported for security tooling:

```ts
import { audit, formatSarif } from "hooktripwire";

const result = await audit({
  targets: [".claude", ".github/workflows"],
  cwd: process.cwd(),
  policy: { allowHosts: ["api.github.com"] },
});

process.stdout.write(formatSarif(result));
```

`scanText()` is available for editor integrations that already own file discovery.

## Security model

HookTripwire is a static heuristic analyzer, not a sandbox or a proof that a hook is safe. It intentionally does not:

- execute or source scanned commands;
- parse shell through a shell process;
- resolve or download remote actions and scripts;
- follow symlinks;
- claim to identify every obfuscated or runtime-generated payload.

Treat every finding as a focused review prompt. Layer HookTripwire with code review, sandboxing, scoped credentials, outbound network controls, immutable dependencies, and runtime monitoring. See [SECURITY.md](SECURITY.md) for vulnerability reporting and supported versions.

## Development

```bash
git clone https://github.com/mockingbird777/hooktripwire.git
cd hooktripwire
npm ci
npm test
npm audit
```

The test suite covers rule true/false positives, allowlists, baselines, deterministic ordering, symlink and binary boundaries, secret redaction, SARIF structure, HTML escaping, policy validation, atomic file output, and CLI exit codes.

Contributions are welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md), follow the [Code of Conduct](CODE_OF_CONDUCT.md), and open an issue when proposing a new detection rule so its threat model and false-positive boundary can be reviewed first.

## License

[MIT](LICENSE) © 2026 mockingbird777
