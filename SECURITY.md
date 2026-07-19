# Security policy

## Supported versions

Security fixes are provided for the latest release on the `main` branch. Until HookTripwire reaches 1.0, minor releases may contain necessary defensive behavior changes.

## Reporting a vulnerability

Please use GitHub’s private vulnerability reporting feature for this repository. Do not open a public issue for a suspected vulnerability, bypass, credential exposure, or denial-of-service input.

Include:

- the affected version or commit;
- the smallest safe reproduction;
- the expected and actual security boundary;
- whether scanned content is exposed, executed, fetched, or written unexpectedly;
- any suggested mitigation.

Avoid including live credentials or third-party private data. You can expect an acknowledgement within seven days. After triage, maintainers will coordinate validation, a fix, and disclosure timing with the reporter.

## Scope

High-priority reports include command execution, symlink traversal, unredacted secrets in reports, report-format injection, unsafe temporary-file handling, remote network access, and inputs that bypass documented resource limits.

Detection gaps and false positives are valuable but are normally handled as rule-quality issues rather than product vulnerabilities unless they contradict an explicit security guarantee.

## Security guarantees

HookTripwire treats scanned files as untrusted data. It does not intentionally execute commands, load remote resources, follow symbolic links, or send telemetry. Generated evidence is redacted and HTML is escaped. Output files are written atomically with owner-only permissions.
