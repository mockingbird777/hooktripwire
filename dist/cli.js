#!/usr/bin/env node
import { access, mkdir, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { audit, VERSION } from "./engine.js";
import { formatResult } from "./formatters.js";
import { createBaseline, loadBaseline, loadPolicy, normalizePolicy } from "./policy.js";
import { RULES } from "./rules.js";
import { isAtLeast, parseSeverity } from "./utils.js";
const HELP = `HookTripwire ${VERSION} — static security auditing for AI agent hooks

Usage:
  hooktripwire [targets...] [options]

Options:
  -f, --format <type>       terminal, json, markdown, sarif, or html
  -o, --output <file>       write the report atomically (use - for stdout)
      --policy <file>       JSON or simple YAML least-privilege policy
      --baseline <file>     suppress matching fingerprints from a baseline
      --write-baseline <f>  write current fingerprints and exit successfully
      --fail-on <severity>  info, low, medium, high, critical, or none [high]
      --include-suppressed  include baselined findings in the report
      --no-color            disable terminal colors
      --list-rules          print the rule catalog
  -h, --help                show help
  -v, --version             show version

Examples:
  hooktripwire .claude .github/workflows
  hooktripwire . --format sarif --output hooktripwire.sarif
  hooktripwire . --write-baseline .hooktripwire-baseline.json
`;
function valueAfter(argv, index, flag) {
    const value = argv[index + 1];
    if (value === undefined || value.startsWith("-"))
        throw new Error(`${flag} requires a value`);
    return value;
}
function parseArguments(argv) {
    const args = {
        targets: [], format: "terminal", failOn: "high", color: process.stdout.isTTY,
        includeSuppressed: false, help: false, version: false, listRules: false,
    };
    const formats = ["terminal", "json", "markdown", "sarif", "html"];
    for (let index = 0; index < argv.length; index += 1) {
        const item = argv[index] ?? "";
        if (item === "--") {
            args.targets.push(...argv.slice(index + 1));
            break;
        }
        if (item === "-h" || item === "--help")
            args.help = true;
        else if (item === "-v" || item === "--version")
            args.version = true;
        else if (item === "--list-rules")
            args.listRules = true;
        else if (item === "--no-color")
            args.color = false;
        else if (item === "--include-suppressed")
            args.includeSuppressed = true;
        else if (item === "-f" || item === "--format") {
            const value = valueAfter(argv, index, item);
            index += 1;
            if (!formats.includes(value))
                throw new Error(`Unknown format: ${value}`);
            args.format = value;
        }
        else if (item === "-o" || item === "--output") {
            args.output = valueAfter(argv, index, item);
            index += 1;
        }
        else if (item === "--policy") {
            args.policy = valueAfter(argv, index, item);
            index += 1;
        }
        else if (item === "--baseline") {
            args.baseline = valueAfter(argv, index, item);
            index += 1;
        }
        else if (item === "--write-baseline") {
            args.writeBaseline = valueAfter(argv, index, item);
            index += 1;
        }
        else if (item === "--fail-on") {
            const value = valueAfter(argv, index, item);
            index += 1;
            if (value === "none")
                args.failOn = undefined;
            else {
                const severity = parseSeverity(value);
                if (severity === undefined)
                    throw new Error(`Unknown severity: ${value}`);
                args.failOn = severity;
            }
        }
        else if (item.startsWith("-"))
            throw new Error(`Unknown option: ${item}`);
        else
            args.targets.push(item);
    }
    return args;
}
async function exists(file) {
    try {
        await access(file);
        return true;
    }
    catch {
        return false;
    }
}
async function autoPolicy(cwd, explicit) {
    if (explicit !== undefined)
        return loadPolicy(path.resolve(cwd, explicit));
    for (const name of [".hooktripwire.json", ".hooktripwire.yml", ".hooktripwire.yaml"]) {
        const candidate = path.join(cwd, name);
        if (await exists(candidate))
            return loadPolicy(candidate);
    }
    return normalizePolicy();
}
async function autoBaseline(cwd, explicit) {
    if (explicit !== undefined)
        return loadBaseline(path.resolve(cwd, explicit));
    const candidate = path.join(cwd, ".hooktripwire-baseline.json");
    return (await exists(candidate)) ? loadBaseline(candidate) : undefined;
}
async function atomicWrite(file, content) {
    const absolute = path.resolve(file);
    await mkdir(path.dirname(absolute), { recursive: true });
    const temporary = path.join(path.dirname(absolute), `.${path.basename(absolute)}.${process.pid}.tmp`);
    await writeFile(temporary, content, { encoding: "utf8", mode: 0o600 });
    await rename(temporary, absolute);
}
function rulesText() {
    return `${RULES.map((rule) => `${rule.id}\t${rule.defaultSeverity.padEnd(8)}\t${rule.title}`).join("\n")}\n`;
}
async function main() {
    let args;
    try {
        args = parseArguments(process.argv.slice(2));
    }
    catch (error) {
        process.stderr.write(`hooktripwire: ${error instanceof Error ? error.message : String(error)}\nTry 'hooktripwire --help'.\n`);
        return 2;
    }
    if (args.help) {
        process.stdout.write(HELP);
        return 0;
    }
    if (args.version) {
        process.stdout.write(`${VERSION}\n`);
        return 0;
    }
    if (args.listRules) {
        process.stdout.write(rulesText());
        return 0;
    }
    try {
        const cwd = process.cwd();
        const policy = await autoPolicy(cwd, args.policy);
        const baseline = args.writeBaseline === undefined ? await autoBaseline(cwd, args.baseline) : undefined;
        const result = await audit({ targets: args.targets, cwd, policy, ...(baseline === undefined ? {} : { baseline }), includeSuppressed: args.includeSuppressed });
        if (args.writeBaseline !== undefined) {
            const output = `${JSON.stringify(createBaseline(result.findings.map((finding) => finding.fingerprint)), null, 2)}\n`;
            await atomicWrite(args.writeBaseline, output);
            process.stdout.write(`Wrote ${result.findings.length} fingerprints to ${args.writeBaseline}\n`);
            return 0;
        }
        const report = formatResult(result, args.format, args.color && args.format === "terminal");
        if (args.output === undefined || args.output === "-")
            process.stdout.write(report);
        else {
            await atomicWrite(args.output, report);
            process.stderr.write(`HookTripwire wrote ${args.format} report to ${args.output}\n`);
        }
        return args.failOn !== undefined && result.findings.some((finding) => finding.suppressed !== true && isAtLeast(finding.severity, args.failOn)) ? 1 : 0;
    }
    catch (error) {
        process.stderr.write(`hooktripwire: ${error instanceof Error ? error.message : String(error)}\n`);
        return 2;
    }
}
process.exitCode = await main();
//# sourceMappingURL=cli.js.map