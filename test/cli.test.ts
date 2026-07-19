import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const cli = path.resolve("dist/cli.js");

function run(args: string[], cwd = process.cwd()) {
  return spawnSync(process.execPath, [cli, ...args], { cwd, encoding: "utf8" });
}

test("version, help, and rule catalog are available", () => {
  assert.equal(run(["--version"]).stdout.trim(), "0.1.0");
  assert.match(run(["--help"]).stdout, /Usage:/);
  assert.match(run(["--list-rules"]).stdout, /HG015/);
});

test("CLI exits one at threshold and zero when disabled", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "hooktripwire-cli-"));
  try {
    await writeFile(path.join(directory, "hook.sh"), "rm -rf /");
    const failing = run([".", "--no-color"], directory);
    assert.equal(failing.status, 1);
    assert.match(failing.stdout, /HG001/);
    assert.equal(run([".", "--fail-on", "none"], directory).status, 0);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test("CLI failure thresholds respect effective severity", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "hooktripwire-threshold-"));
  try {
    await writeFile(path.join(directory, "workflow.yml"), "uses: actions/checkout@v4");
    assert.equal(run(["."], directory).status, 0);
    assert.equal(run([".", "--fail-on", "medium"], directory).status, 1);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test("CLI atomically writes SARIF with private permissions", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "hooktripwire-output-"));
  try {
    await writeFile(path.join(directory, "hook.sh"), "rm -rf /");
    const result = run([".", "--format", "sarif", "--output", "reports/result.sarif", "--fail-on", "none"], directory);
    assert.equal(result.status, 0, result.stderr);
    const output = JSON.parse(await readFile(path.join(directory, "reports", "result.sarif"), "utf8")) as { version: string };
    assert.equal(output.version, "2.1.0");
    assert.equal((await stat(path.join(directory, "reports", "result.sarif"))).mode & 0o777, 0o600);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test("CLI accepts an explicit stdout output target", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "hooktripwire-stdout-"));
  try {
    await writeFile(path.join(directory, "hook.sh"), "rm -rf /");
    const result = run([".", "--format", "json", "--output", "-", "--fail-on", "none"], directory);
    assert.equal(result.status, 0, result.stderr);
    const output = JSON.parse(result.stdout) as { findings: Array<{ ruleId: string }> };
    assert.equal(output.findings[0]?.ruleId, "HG001");
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test("CLI creates and consumes a baseline", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "hooktripwire-cli-baseline-"));
  try {
    await writeFile(path.join(directory, "hook.sh"), "rm -rf /");
    assert.equal(run([".", "--write-baseline", ".hooktripwire-baseline.json"], directory).status, 0);
    const baseline = JSON.parse(await readFile(path.join(directory, ".hooktripwire-baseline.json"), "utf8")) as { fingerprints: string[] };
    assert.equal(baseline.fingerprints.length, 1);
    const scan = run(["."], directory);
    assert.equal(scan.status, 0);
    assert.match(scan.stdout, /1 finding suppressed/);
    assert.equal(run([".", "--include-suppressed"], directory).status, 0);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test("CLI reports usage and configuration errors with exit code two", async () => {
  assert.equal(run(["--wat"]).status, 2);
  const hostile = run(["missing\u001b[2J.yml"]);
  assert.equal(hostile.status, 2);
  assert.equal(hostile.stderr.includes("\u001b[2J"), false);
  assert.ok(hostile.stderr.includes("\\u001b[2J"));
  const directory = await mkdtemp(path.join(os.tmpdir(), "hooktripwire-cli-policy-"));
  try {
    await writeFile(path.join(directory, "bad.json"), "not-json");
    const result = run([".", "--policy", "bad.json"], directory);
    assert.equal(result.status, 2);
    assert.match(result.stderr, /Could not parse policy/);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
