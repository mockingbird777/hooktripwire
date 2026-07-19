import { spawn } from "node:child_process";
import { readdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const directory = fileURLToPath(new URL("../dist-test/test/", import.meta.url));
const coverage = process.argv.slice(2).includes("--coverage");
const files = (await readdir(directory, { withFileTypes: true }))
  .filter((entry) => entry.isFile() && entry.name.endsWith(".test.js"))
  .map((entry) => path.join(directory, entry.name))
  .sort();

if (files.length === 0) throw new Error(`No compiled tests found in ${directory}`);

const args = [
  ...(coverage ? ["--experimental-test-coverage"] : []),
  "--test",
  "--test-reporter=spec",
  ...files,
];
const child = spawn(process.execPath, args, { stdio: "inherit" });
const exitCode = await new Promise((resolve, reject) => {
  child.once("error", reject);
  child.once("exit", (code) => resolve(code ?? 1));
});

process.exitCode = exitCode;
