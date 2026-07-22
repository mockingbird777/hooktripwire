import path from "node:path";
import { discover } from "./discovery.js";
import { DEFAULT_POLICY, normalizePolicy } from "./policy.js";
import { RULES, runRules } from "./rules.js";
import { attachHookPathFindings, mapHookPaths, validateMaxHookDepth } from "./hookgraph.js";
import { compareText, fingerprint, sortFindings } from "./utils.js";
import type { AuditRequest, Finding, Policy, ScanInput, ScanResult } from "./types.js";

export const VERSION = "0.3.0";
const metadata = new Map(RULES.map((rule) => [rule.id, rule]));

function effectivePolicy(input: AuditRequest["policy"]): Policy {
  return normalizePolicy(input ?? DEFAULT_POLICY);
}

function findingsFor(input: ScanInput, policy: Policy, baseline: ReadonlySet<string>): Finding[] {
  return runRules(input, policy).map((raw) => {
    const meta = metadata.get(raw.ruleId);
    if (meta === undefined) throw new Error(`Internal error: metadata missing for ${raw.ruleId}`);
    const id = fingerprint(raw.ruleId, input.displayPath, raw.line, raw.evidence);
    const suppressed = baseline.has(id);
    return {
      ruleId: meta.id,
      title: meta.title,
      severity: policy.severity[meta.id] ?? raw.severity ?? meta.defaultSeverity,
      message: raw.message ?? meta.description,
      evidence: raw.evidence,
      remediation: meta.remediation,
      location: { path: input.displayPath, line: raw.line, column: raw.column },
      fingerprint: id,
      tags: meta.tags,
      ...(suppressed ? { suppressed: true, suppressionReason: "baseline" } : {}),
    };
  });
}

export function scanText(content: string, displayPath = "input.sh", policyInput: AuditRequest["policy"] = {}): readonly Finding[] {
  const policy = effectivePolicy(policyInput);
  return sortFindings(findingsFor({ path: displayPath, displayPath, content }, policy, new Set()));
}

export async function audit(request: AuditRequest): Promise<ScanResult> {
  const cwd = path.resolve(request.cwd ?? process.cwd());
  const policy = effectivePolicy(request.policy);
  const baseline = new Set(request.baseline?.fingerprints ?? []);
  const discovered = await discover(request.targets, cwd, policy);
  if (request.maxHookDepth !== undefined) validateMaxHookDepth(request.maxHookDepth);
  const mapped = request.mapHooks === true
    ? await mapHookPaths(discovered.files, cwd, policy, request.maxHookDepth)
    : undefined;
  const files = [...discovered.files, ...(mapped?.files ?? [])]
    .sort((left, right) => compareText(left.displayPath, right.displayPath));
  const all = sortFindings(files.flatMap((input) => findingsFor(input, policy, baseline)));
  const suppressedCount = all.filter((finding) => finding.suppressed === true).length;
  const findings = request.includeSuppressed === true ? all : all.filter((finding) => finding.suppressed !== true);
  const skipped = new Map<string, (typeof discovered.skipped)[number]>();
  for (const item of [...discovered.skipped, ...(mapped?.skipped ?? [])]) skipped.set(`${item.path}\0${item.reason}`, item);
  return {
    version: VERSION,
    scannedAt: request.now ?? new Date().toISOString(),
    root: cwd,
    filesScanned: files.length,
    bytesScanned: discovered.bytes + (mapped?.bytes ?? 0),
    findings,
    suppressedCount,
    skippedFiles: [...skipped.values()].sort((left, right) => compareText(left.path, right.path) || compareText(left.reason, right.reason)),
    ...(mapped === undefined ? {} : { hookPaths: attachHookPathFindings(mapped.paths, findings) }),
  };
}
