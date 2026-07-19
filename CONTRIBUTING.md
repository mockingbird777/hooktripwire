# Contributing to HookTripwire

Thank you for helping make agent automation safer. Contributions of detection rules, false-positive reductions, report integrations, tests, and documentation are welcome.

## Before opening a pull request

1. Search existing issues and discussions.
2. Open an issue for a new rule or a behavior change. Describe the security boundary, a realistic unsafe example, and at least one safe look-alike that must not be flagged.
3. Keep the engine offline and dependency-light. A rule must never execute, source, import, or remotely resolve scanned content.
4. Add tests for true positives, false positives, redaction, and deterministic output where applicable.

## Local workflow

```bash
npm ci
npm test
npm audit
npm pack --dry-run
```

Node.js 20 is the minimum supported version. TypeScript is strict, including unchecked indexed access and exact optional properties.

## Rule design checklist

- Use a stable `HG###` identifier and actionable title.
- Explain the trust boundary rather than merely restating a regular expression.
- Prefer a narrow, reviewable signal over a broad keyword match.
- Include a concrete least-privilege remediation.
- Redact credentials before evidence reaches any formatter.
- Keep output independent of locale, platform directory order, and object insertion order.
- Verify the rule against JSON, YAML, Markdown, and shell contexts it claims to support.

## Commits and pull requests

Keep changes focused. Explain what changed, why the security trade-off is sound, how it was tested, and whether users need to update a policy or baseline. Screenshots are useful for HTML or Pages changes but do not replace tests.

By participating, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md). Security vulnerabilities belong in the private process described in [SECURITY.md](SECURITY.md), not in a public issue.
