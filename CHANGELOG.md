# Changelog

All notable changes to HookTripwire are documented here. The project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Add opt-in HookGraph analysis with `--map-hooks` and bounded `--max-hook-depth` traversal. It maps statically provable JSON/JSONC/YAML hook commands through literal repository-local shell, Node.js, Python, and sourced-script references, associates leaf findings, and reports dynamic, missing, cyclic, depth-limited, ignored, unreadable, symlinked, and out-of-root boundaries without executing or fetching content.
- Expose HookGraph through the library result, terminal, JSON, Markdown, self-contained HTML, built-in demo, and composite Action while retaining unchanged output when mapping is not requested.

## [0.2.0] - 2026-07-20

### Fixed

- Run compiled tests through a shell-independent Node.js runner so the Windows CI matrix does not depend on glob expansion.
- Assert owner-only output modes on POSIX, where permission bits are enforced, while retaining the `0600` write mode in production.

### Added

- Add a deterministic `--demo` scan so first-time users can see actionable findings without preparing input files.
- Add a zero-install composite GitHub Action backed by the same offline CLI and covered by a workflow smoke test.
- Add a 1280×640 repository social preview and a first-visit README experience built around verified demo output.

## [0.1.0] - 2026-07-19

### Added

- Offline static analysis for JSON, JSONC, YAML, Markdown, shell, TOML, and common automation files.
- Fifteen security rules covering destructive commands, remote execution, exfiltration, shell injection, approvals, filesystem/network scope, supply-chain pinning, credentials, and TLS.
- Terminal, JSON, Markdown, SARIF 2.1, and self-contained HTML reports.
- Least-privilege JSON/YAML policies, severity overrides, host/action allowlists, path ignores, and size limits.
- Stable finding fingerprints and baseline-driven gradual adoption.
- Safe recursive discovery without symlink traversal, binary parsing, or command execution.
- Node.js library API, CLI failure thresholds, and atomic report output.
- Interactive GitHub Pages security lab and complete contributor/security documentation.
- Fifty-four tests across rules, false-positive boundaries, policies, discovery, reports, and CLI behavior.
- Complete credential redaction, schema-valid SARIF, restrictive HTML CSP, randomized atomic output files, no-follow reads, format-specific output escaping, and strict policy validation.
- Multiline YAML grants, unquoted shell evaluation, broad workflow permissions, mutable container actions, ordered integrity verification, and additional TLS and destructive-command variants.

[Unreleased]: https://github.com/mockingbird777/hooktripwire/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/mockingbird777/hooktripwire/releases/tag/v0.2.0
[0.1.0]: https://github.com/mockingbird777/hooktripwire/releases/tag/v0.1.0
