export const severities = ["info", "low", "medium", "high", "critical"] as const;
export type Severity = (typeof severities)[number];

export interface Location {
  readonly path: string;
  readonly line: number;
  readonly column: number;
}

export interface Finding {
  readonly ruleId: string;
  readonly title: string;
  readonly severity: Severity;
  readonly message: string;
  readonly evidence: string;
  readonly remediation: string;
  readonly location: Location;
  readonly fingerprint: string;
  readonly tags: readonly string[];
  readonly suppressed?: boolean;
  readonly suppressionReason?: string;
}

export interface RuleMetadata {
  readonly id: string;
  readonly title: string;
  readonly defaultSeverity: Severity;
  readonly description: string;
  readonly remediation: string;
  readonly tags: readonly string[];
}

export interface Policy {
  readonly disabledRules: readonly string[];
  readonly severity: Readonly<Record<string, Severity>>;
  readonly allowHosts: readonly string[];
  readonly trustedActions: readonly string[];
  readonly ignorePaths: readonly string[];
  readonly maxFileBytes: number;
}

export interface Baseline {
  readonly version: 1;
  readonly fingerprints: readonly string[];
}

export interface ScanInput {
  readonly path: string;
  readonly displayPath: string;
  readonly content: string;
}

export interface ScanResult {
  readonly version: string;
  readonly scannedAt: string;
  readonly root: string;
  readonly filesScanned: number;
  readonly bytesScanned: number;
  readonly findings: readonly Finding[];
  readonly suppressedCount: number;
  readonly skippedFiles: readonly SkippedFile[];
  readonly hookPaths?: readonly HookPath[];
}

export interface SkippedFile {
  readonly path: string;
  readonly reason: string;
}

export type HookLauncher = "direct" | "sh" | "bash" | "zsh" | "node" | "python" | "source";

export type HookPathIncompleteReason =
  | "cycle"
  | "depth-limit"
  | "dynamic-reference"
  | "outside-root"
  | "non-local-reference"
  | "symbolic-link"
  | "missing-file"
  | "ignored"
  | "unreadable"
  | "command-limit"
  | "file-limit"
  | "read-limit"
  | "edge-limit"
  | "path-limit";

export interface HookEdge {
  readonly from: Location;
  readonly launcher: HookLauncher;
  /** A redacted, bounded literal path or the marker `<dynamic>`. */
  readonly reference: string;
  /** Present only when the reference was safely resolved inside the audit root. */
  readonly to?: string;
}

/** A statically provable local path from one hook command to a terminal script. */
export interface HookPath {
  readonly entry: Location;
  readonly hook: string;
  readonly edges: readonly HookEdge[];
  readonly leaf?: string;
  readonly findingFingerprints: readonly string[];
  readonly incomplete?: HookPathIncompleteReason;
}

export type OutputFormat = "terminal" | "json" | "markdown" | "sarif" | "html";

export interface AuditOptions {
  readonly cwd?: string;
  readonly policy?: Partial<Policy>;
  readonly baseline?: Baseline;
  readonly includeSuppressed?: boolean;
  readonly now?: string;
  readonly mapHooks?: boolean;
  readonly maxHookDepth?: number;
}

export interface AuditRequest extends AuditOptions {
  readonly targets: readonly string[];
}
