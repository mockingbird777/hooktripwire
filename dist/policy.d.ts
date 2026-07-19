import type { Baseline, Policy } from "./types.js";
export declare const DEFAULT_POLICY: Policy;
export declare function normalizePolicy(input?: Partial<Policy>): Policy;
export declare function loadPolicy(file: string): Promise<Policy>;
export declare function loadBaseline(file: string): Promise<Baseline>;
export declare function createBaseline(fingerprints: readonly string[]): Baseline;
//# sourceMappingURL=policy.d.ts.map