# Changelog

All notable changes to HookTripwire are documented here. The project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/mockingbird777/hooktripwire/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mockingbird777/hooktripwire/releases/tag/v0.1.0
