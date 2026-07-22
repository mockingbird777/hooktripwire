import type { Policy, ScanInput, SkippedFile } from "./types.js";
export interface DiscoveryResult {
    readonly files: readonly ScanInput[];
    readonly skipped: readonly SkippedFile[];
    readonly bytes: number;
}
interface FileIdentity {
    readonly device: number;
    readonly inode: number;
}
export interface SafeReadResult {
    readonly input?: ScanInput;
    readonly skipped?: SkippedFile;
    readonly bytes: number;
}
/**
 * Read one already-resolved file without following its final symbolic link.
 * Callers that accept graph references must additionally validate root
 * containment and every parent path component before calling this helper.
 */
export declare function safeReadFile(absolute: string, displayPath: string, policy: Policy, expected?: FileIdentity): Promise<SafeReadResult>;
export declare function discover(targets: readonly string[], cwd: string, policy: Policy): Promise<DiscoveryResult>;
export {};
//# sourceMappingURL=discovery.d.ts.map