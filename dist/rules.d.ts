import type { Policy, RuleMetadata, ScanInput, Severity } from "./types.js";
export interface RuleHit {
    readonly ruleId: string;
    readonly line: number;
    readonly column: number;
    readonly evidence: string;
    readonly message?: string;
    readonly severity?: Severity;
}
export declare const RULES: readonly RuleMetadata[];
export declare function runRules(input: ScanInput, policy: Policy): RuleHit[];
//# sourceMappingURL=rules.d.ts.map