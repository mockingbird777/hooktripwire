import { type Finding, type Severity } from "./types.js";
export declare function severityRank(severity: Severity): number;
export declare function isAtLeast(actual: Severity, threshold: Severity): boolean;
export declare function sha256(value: string): string;
export declare function fingerprint(ruleId: string, displayPath: string, line: number, normalizedEvidence: string): string;
export declare function redact(value: string): string;
export declare function compactEvidence(value: string, limit?: number): string;
export declare function escapeHtml(value: string): string;
export declare function escapeMarkdown(value: string): string;
export declare function toPosix(value: string): string;
export declare function normalizeRelative(root: string, absolute: string): string;
export declare function globMatches(pattern: string, candidate: string): boolean;
export declare function sortFindings(findings: readonly Finding[]): Finding[];
export declare function lineColumn(content: string, offset: number): {
    line: number;
    column: number;
};
export declare function parseSeverity(value: string): Severity | undefined;
export declare function safeJson(value: unknown): string;
//# sourceMappingURL=utils.d.ts.map