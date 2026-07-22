import type { Finding, HookPath, Policy, ScanInput, SkippedFile } from "./types.js";
export interface HookMapResult {
    readonly files: readonly ScanInput[];
    readonly bytes: number;
    readonly skipped: readonly SkippedFile[];
    readonly paths: readonly HookPath[];
}
export declare function validateMaxHookDepth(value: number | undefined): number;
export declare function mapHookPaths(initialFiles: readonly ScanInput[], cwd: string, policy: Policy, requestedDepth?: number): Promise<HookMapResult>;
export declare function attachHookPathFindings(paths: readonly HookPath[], findings: readonly Finding[]): readonly HookPath[];
//# sourceMappingURL=hookgraph.d.ts.map