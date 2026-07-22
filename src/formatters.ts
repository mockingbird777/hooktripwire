import { RULES } from "./rules.js";
import { escapeHtml, escapeMarkdown, safeJson, severityRank, toPosix, visibleControls } from "./utils.js";
import type { Finding, HookPath, OutputFormat, ScanResult, Severity } from "./types.js";

const icons: Record<Severity, string> = { critical: "✖", high: "▲", medium: "◆", low: "●", info: "·" };
const ansi: Record<Severity, string> = { critical: "\u001b[91m", high: "\u001b[31m", medium: "\u001b[33m", low: "\u001b[36m", info: "\u001b[90m" };

function counts(findings: readonly Finding[]): Record<Severity, number> {
  return {
    critical: findings.filter((finding) => finding.severity === "critical").length,
    high: findings.filter((finding) => finding.severity === "high").length,
    medium: findings.filter((finding) => finding.severity === "medium").length,
    low: findings.filter((finding) => finding.severity === "low").length,
    info: findings.filter((finding) => finding.severity === "info").length,
  };
}

function singleLine(value: string): string {
  return visibleControls(value).replaceAll("\r", "\\r").replaceAll("\n", "\\n").replaceAll("\t", "\\t");
}

function findingIds(path: HookPath, result: ScanResult): string[] {
  const byFingerprint = new Map(result.findings.map((finding) => [finding.fingerprint, finding.ruleId]));
  return [...new Set(path.findingFingerprints.map((fingerprint) => byFingerprint.get(fingerprint)).filter((id): id is string => id !== undefined))].sort();
}

export function formatTerminal(result: ScanResult, color = false): string {
  const lines: string[] = [];
  for (const finding of result.findings) {
    const prefix = `${icons[finding.severity]} ${finding.severity.toUpperCase().padEnd(8)} ${finding.ruleId}`;
    const colored = color ? `${ansi[finding.severity]}${prefix}\u001b[0m` : prefix;
    lines.push(`${colored}  ${singleLine(finding.location.path)}:${finding.location.line}:${finding.location.column}`);
    lines.push(`  ${singleLine(finding.title)} — ${singleLine(finding.message)}`);
    lines.push(`  Evidence: ${singleLine(finding.evidence)}`);
    lines.push(`  Fix: ${singleLine(finding.remediation)}`);
    if (finding.suppressed === true) lines.push(`  Suppressed: ${singleLine(finding.suppressionReason ?? "policy")}`);
    lines.push("");
  }
  if (result.hookPaths !== undefined) {
    lines.push(`Hook execution paths (${result.hookPaths.length}):`);
    if (result.hookPaths.length === 0) lines.push("  No statically provable local hook paths discovered.");
    for (const [index, hookPath] of result.hookPaths.entries()) {
      lines.push(`  ${index + 1}. ${singleLine(hookPath.hook)}  ${singleLine(hookPath.entry.path)}:${hookPath.entry.line}:${hookPath.entry.column}`);
      for (const edge of hookPath.edges) {
        lines.push(`     → ${singleLine(edge.to ?? edge.reference)}  (${edge.launcher}, ${singleLine(edge.from.path)}:${edge.from.line})`);
      }
      const ids = findingIds(hookPath, result);
      if (ids.length > 0) lines.push(`     Findings: ${ids.join(", ")}`);
      if (hookPath.incomplete !== undefined) lines.push(`     Incomplete: ${hookPath.incomplete}`);
    }
    lines.push("");
  }
  const summary = counts(result.findings);
  lines.push(`HookTripwire scanned ${result.filesScanned} file${result.filesScanned === 1 ? "" : "s"} (${result.bytesScanned} bytes).`);
  lines.push(`${result.findings.length} finding${result.findings.length === 1 ? "" : "s"}: ${summary.critical} critical, ${summary.high} high, ${summary.medium} medium, ${summary.low} low, ${summary.info} info.`);
  if (result.suppressedCount > 0) lines.push(`${result.suppressedCount} finding${result.suppressedCount === 1 ? "" : "s"} suppressed by baseline.`);
  if (result.skippedFiles.length > 0) lines.push(`${result.skippedFiles.length} file${result.skippedFiles.length === 1 ? "" : "s"} skipped safely.`);
  return `${lines.join("\n")}\n`;
}

export function formatJson(result: ScanResult): string {
  return `${JSON.stringify(result, null, 2)}\n`;
}

export function formatMarkdown(result: ScanResult): string {
  const summary = counts(result.findings);
  const lines = [
    "# HookTripwire security audit",
    "",
    `Scanned **${result.filesScanned}** files. Found **${result.findings.length}** issues (${summary.critical} critical, ${summary.high} high, ${summary.medium} medium).`,
    "",
    "| Severity | Rule | Location | Finding | Evidence |",
    "|---|---|---|---|---|",
  ];
  for (const finding of result.findings) {
    lines.push(`| ${finding.severity.toUpperCase()} | ${finding.ruleId} | ${markdownCode(`${finding.location.path}:${finding.location.line}`)} | ${escapeMarkdown(finding.title)} | ${markdownCode(finding.evidence)} |`);
  }
  if (result.findings.length === 0) lines.push("| — | — | — | No findings | — |");
  if (result.hookPaths !== undefined) {
    lines.push("", "## Hook execution paths", "");
    if (result.hookPaths.length === 0) lines.push("No statically provable local hook paths discovered.");
    for (const hookPath of result.hookPaths) {
      lines.push(`- **${escapeMarkdown(hookPath.hook)}** at ${markdownCode(`${hookPath.entry.path}:${hookPath.entry.line}:${hookPath.entry.column}`)}`);
      for (const edge of hookPath.edges) {
        lines.push(`  - ${markdownCode(`${edge.from.path}:${edge.from.line}`)} → ${markdownCode(edge.to ?? edge.reference)} (${edge.launcher})`);
      }
      const ids = findingIds(hookPath, result);
      if (ids.length > 0) lines.push(`  - Findings: ${ids.map(markdownCode).join(", ")}`);
      if (hookPath.incomplete !== undefined) lines.push(`  - Incomplete: ${markdownCode(hookPath.incomplete)}`);
    }
  }
  lines.push("", "## Remediation", "");
  for (const finding of result.findings) {
    lines.push(`- **${finding.ruleId} at ${markdownCode(`${finding.location.path}:${finding.location.line}`)}:** ${escapeMarkdown(finding.remediation)}`);
  }
  if (result.findings.length === 0) lines.push("No remediation required.");
  lines.push("", "_Generated by HookTripwire._", "");
  return lines.join("\n");
}

function markdownCode(value: string): string {
  return `<code>${escapeHtml(visibleControls(value)).replaceAll("|", "&#124;").replace(/[\r\n]+/g, " ")}</code>`;
}

function sarifLevel(severity: Severity): "error" | "warning" | "note" {
  if (severity === "critical" || severity === "high") return "error";
  if (severity === "medium") return "warning";
  return "note";
}

function sarifUri(value: string): string {
  return toPosix(value).split("/").map((segment) => encodeURIComponent(segment)).join("/");
}

export function formatSarif(result: ScanResult): string {
  const used = new Set(result.findings.map((finding) => finding.ruleId));
  const sarif = {
    $schema: "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: {
        driver: {
          name: "HookTripwire",
          version: result.version,
          informationUri: "https://github.com/mockingbird777/hooktripwire",
          rules: RULES.filter((rule) => used.has(rule.id)).map((rule) => ({
            id: rule.id,
            name: rule.title.replace(/[^A-Za-z0-9]+/g, ""),
            shortDescription: { text: rule.title },
            fullDescription: { text: rule.description },
            help: { text: rule.remediation },
            properties: { tags: rule.tags, defaultSeverity: rule.defaultSeverity },
          })),
        },
      },
      results: result.findings.map((finding) => ({
        ruleId: finding.ruleId,
        level: sarifLevel(finding.severity),
        message: { text: `${finding.title}: ${finding.message}` },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: sarifUri(finding.location.path) },
            region: { startLine: finding.location.line, startColumn: finding.location.column },
          },
        }],
        partialFingerprints: { hooktripwireFingerprint: finding.fingerprint },
        properties: { severity: finding.severity, evidence: finding.evidence },
      })),
    }],
  };
  return `${JSON.stringify(sarif, null, 2)}\n`;
}

export function formatHtml(result: ScanResult): string {
  const summary = counts(result.findings);
  const cards = result.findings.map((finding) => `<article class="finding severity-${finding.severity}">
    <div class="finding-head"><span class="badge">${escapeHtml(finding.severity)}</span><strong>${escapeHtml(finding.ruleId)} · ${escapeHtml(finding.title)}</strong></div>
    <p class="location">${escapeHtml(singleLine(finding.location.path))}:${finding.location.line}:${finding.location.column}</p>
    <p>${escapeHtml(singleLine(finding.message))}</p>
    <pre><code>${escapeHtml(singleLine(finding.evidence))}</code></pre>
    <p class="fix"><span>Fix</span> ${escapeHtml(singleLine(finding.remediation))}</p>
  </article>`).join("\n") || '<div class="empty">No unsafe hook patterns detected.</div>';
  const hookCards = result.hookPaths?.map((hookPath) => {
    const ids = findingIds(hookPath, result);
    const steps = hookPath.edges.map((edge) => `<li><code>${escapeHtml(singleLine(edge.from.path))}:${edge.from.line}</code><span>→</span><code>${escapeHtml(singleLine(edge.to ?? edge.reference))}</code><small>${edge.launcher}</small></li>`).join("");
    return `<article class="hook-path"><h3>${escapeHtml(singleLine(hookPath.hook))}</h3><p class="location">${escapeHtml(singleLine(hookPath.entry.path))}:${hookPath.entry.line}:${hookPath.entry.column}</p><ol>${steps}</ol>${ids.length === 0 ? "" : `<p><strong>Findings</strong> ${ids.map((id) => `<code>${escapeHtml(id)}</code>`).join(" ")}</p>`}${hookPath.incomplete === undefined ? "" : `<p class="incomplete"><strong>Incomplete</strong> ${escapeHtml(hookPath.incomplete)}</p>`}</article>`;
  }).join("\n");
  const hookSection = result.hookPaths === undefined ? "" : `<section class="hook-map" aria-labelledby="hook-paths-title"><h2 id="hook-paths-title">Hook execution paths</h2>${result.hookPaths.length === 0 ? '<div class="empty">No statically provable local hook paths discovered.</div>' : hookCards}</section>`;
  const payload = safeJson({ counts: summary, filesScanned: result.filesScanned, findings: result.findings.length, ...(result.hookPaths === undefined ? {} : { hookPaths: result.hookPaths.length }) });
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'">
<meta name="referrer" content="no-referrer"><meta name="color-scheme" content="dark"><title>HookTripwire security audit</title>
<style>
:root{font-family:Inter,ui-sans-serif,system-ui,sans-serif;color:#eaf0ff;background:#070b14}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 15% -10%,#25366e 0,transparent 34rem),#070b14;min-height:100vh}.wrap{width:min(1060px,92vw);margin:auto;padding:64px 0}header{display:flex;justify-content:space-between;gap:32px;align-items:end;border-bottom:1px solid #24304a;padding-bottom:28px}.eyebrow{color:#7fd5c7;text-transform:uppercase;letter-spacing:.16em;font-size:12px;font-weight:800}h1{font-size:clamp(36px,7vw,72px);margin:7px 0 0;letter-spacing:-.055em}h2{margin:38px 0 14px}header p{max-width:480px;color:#98a8c7;line-height:1.6}.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:24px 0 34px}.stat{padding:18px;border:1px solid #24304a;border-radius:16px;background:#0d1422cc}.stat strong{font-size:28px;display:block}.stat span{color:#8797b5;font-size:12px;text-transform:uppercase}.finding{position:relative;padding:24px 26px;margin:14px 0;border:1px solid #25304a;border-left:4px solid #7d8cad;border-radius:14px;background:#0c1320e8;box-shadow:0 12px 44px #0004}.severity-critical{border-left-color:#ff4773}.severity-high{border-left-color:#ff754c}.severity-medium{border-left-color:#ffc857}.severity-low{border-left-color:#51d7c7}.finding-head{display:flex;gap:12px;align-items:center}.badge{font-size:10px;text-transform:uppercase;letter-spacing:.1em;background:#202a40;padding:5px 8px;border-radius:6px}.location{color:#8e9db9;font:12px ui-monospace,monospace}.finding p{line-height:1.55;color:#bac6dc}pre{white-space:pre-wrap;word-break:break-word;background:#070b14;padding:14px;border-radius:9px;color:#aee9de;border:1px solid #1c273b}.fix span{color:#7fd5c7;font-weight:800;text-transform:uppercase;font-size:11px;margin-right:8px}.hook-path{padding:18px 22px;margin:12px 0;border:1px solid #29443f;border-radius:14px;background:#0b1918}.hook-path h3{margin:0}.hook-path ol{padding-left:22px}.hook-path li{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:8px 0}.hook-path code{word-break:break-all}.hook-path small{color:#7fd5c7}.incomplete{color:#ffc857}.empty{padding:48px;text-align:center;border:1px solid #24443f;background:#0b1d1a;border-radius:16px;color:#8eebd9}footer{color:#6f7e99;font-size:12px;margin-top:36px} @media(max-width:700px){header{display:block}.stats{grid-template-columns:repeat(2,1fr)}}
</style></head><body><main class="wrap"><header><div><div class="eyebrow">Offline · deterministic · zero telemetry</div><h1>HookTripwire</h1></div><p>Static security audit for AI coding-agent hooks and automation. Commands were analyzed as text and never executed.</p></header>
<section class="stats"><div class="stat"><strong>${result.filesScanned}</strong><span>files</span></div><div class="stat"><strong>${summary.critical}</strong><span>critical</span></div><div class="stat"><strong>${summary.high}</strong><span>high</span></div><div class="stat"><strong>${summary.medium}</strong><span>medium</span></div></section>
${hookSection}<section>${cards}</section><footer>Generated by HookTripwire ${escapeHtml(result.version)} · ${escapeHtml(result.scannedAt)}</footer></main><script type="application/json" id="hooktripwire-summary">${payload}</script></body></html>\n`;
}

export function formatResult(result: ScanResult, format: OutputFormat, color = false): string {
  switch (format) {
    case "terminal": return formatTerminal(result, color);
    case "json": return formatJson(result);
    case "markdown": return formatMarkdown(result);
    case "sarif": return formatSarif(result);
    case "html": return formatHtml(result);
  }
}
