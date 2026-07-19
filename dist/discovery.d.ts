import type { Policy, ScanInput, SkippedFile } from "./types.js";
export interface DiscoveryResult {
    readonly files: readonly ScanInput[];
    readonly skipped: readonly SkippedFile[];
    readonly bytes: number;
}
export declare function discover(targets: readonly string[], cwd: string, policy: Policy): Promise<DiscoveryResult>;
//# sourceMappingURL=discovery.d.ts.map