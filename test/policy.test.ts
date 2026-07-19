import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createBaseline, loadBaseline, loadPolicy, normalizePolicy } from "../src/policy.js";
import { globMatches, redact } from "../src/utils.js";

test("normalizes policy collections and host case", () => {
  const policy = normalizePolicy({ allowHosts: ["API.EXAMPLE.COM", "api.example.com"], disabledRules: ["HG002", "HG002"] });
  assert.deepEqual(policy.allowHosts, ["api.example.com"]);
  assert.deepEqual(policy.disabledRules, ["HG002"]);
  assert.ok(policy.ignorePaths.includes("node_modules/**"));
});

test("rejects invalid policy values", () => {
  assert.throws(() => normalizePolicy({ maxFileBytes: 0 }), /maxFileBytes/);
  assert.throws(() => normalizePolicy({ severity: { HG001: "urgent" as never } }), /Invalid severity/);
  assert.throws(() => normalizePolicy({ disabledRules: [42] as never }), /array of strings/);
});

test("loads JSON and safe YAML policies", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "hooktripwire-policy-"));
  try {
    const json = path.join(directory, "policy.json");
    const yaml = path.join(directory, "policy.yml");
    await writeFile(json, '{"allowHosts":["a.test"],"severity":{"HG007":"high"}}');
    await writeFile(yaml, "allowHosts:\n  - b.test\ndisabledRules: [HG011, HG014]\nseverity:\n  HG007: critical\nmaxFileBytes: 2048\n");
    assert.deepEqual((await loadPolicy(json)).allowHosts, ["a.test"]);
    assert.equal((await loadPolicy(yaml)).severity.HG007, "critical");
    assert.deepEqual((await loadPolicy(yaml)).disabledRules, ["HG011", "HG014"]);
    assert.equal((await loadPolicy(yaml)).maxFileBytes, 2048);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test("YAML parser rejects tags and executable-looking syntax", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "hooktripwire-yaml-"));
  try {
    const yaml = path.join(directory, "policy.yml");
    await writeFile(yaml, "allowHosts: !!js/function >\n  process.exit()\n");
    await assert.rejects(loadPolicy(yaml), /Unsupported YAML|Unexpected YAML/);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test("baseline creation and loading deduplicates fingerprints", async () => {
  const baseline = createBaseline(["b", "a", "b"]);
  assert.deepEqual(baseline, { version: 1, fingerprints: ["a", "b"] });
  const directory = await mkdtemp(path.join(os.tmpdir(), "hooktripwire-baseline-"));
  try {
    const file = path.join(directory, "baseline.json");
    await writeFile(file, JSON.stringify(baseline));
    assert.deepEqual(await loadBaseline(file), baseline);
    await writeFile(file, '{"version":2,"fingerprints":[]}');
    await assert.rejects(loadBaseline(file), /version/);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test("glob matching handles nested paths without regex injection", () => {
  assert.equal(globMatches("fixtures/**", "fixtures/nested/file.yml"), true);
  assert.equal(globMatches("*.lock", "package.lock"), true);
  assert.equal(globMatches("a+b/**", "aaab/file"), false);
});

test("redaction covers assignments, bearer tokens, and credential URLs", () => {
  const output = redact('api_key="secret123456" Bearer abcdefghijkl https://alice:hunter2@example.test');
  assert.equal(output.includes("secret123456"), false);
  assert.equal(output.includes("abcdefghijkl"), false);
  assert.equal(output.includes("hunter2"), false);
});
