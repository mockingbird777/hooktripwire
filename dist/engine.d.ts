import type { AuditRequest, Finding, ScanResult } from "./types.js";
export declare const VERSION = "0.2.0";
export declare function scanText(content: string, displayPath?: string, policyInput?: AuditRequest["policy"]): readonly Finding[];
export declare function audit(request: AuditRequest): Promise<ScanResult>;
//# sourceMappingURL=engine.d.ts.map