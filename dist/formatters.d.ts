import type { OutputFormat, ScanResult } from "./types.js";
export declare function formatTerminal(result: ScanResult, color?: boolean): string;
export declare function formatJson(result: ScanResult): string;
export declare function formatMarkdown(result: ScanResult): string;
export declare function formatSarif(result: ScanResult): string;
export declare function formatHtml(result: ScanResult): string;
export declare function formatResult(result: ScanResult, format: OutputFormat, color?: boolean): string;
//# sourceMappingURL=formatters.d.ts.map