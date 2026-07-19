import { readFile } from "node:fs/promises";
import path from "node:path";
import { parseSeverity } from "./utils.js";
import type { Baseline, Policy, Severity } from "./types.js";

export const DEFAULT_POLICY: Policy = Object.freeze({
  disabledRules: [],
  severity: {},
  allowHosts: ["localhost", "127.0.0.1", "::1"],
  trustedActions: [],
  ignorePaths: [
    ".git/**",
    "node_modules/**",
    "dist/**",
    "build/**",
    "coverage/**",
    "vendor/**",
    "*.lock",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
  ],
  maxFileBytes: 1_048_576,
});

function strings(value: unknown, field: string): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
    throw new Error(`Policy field "${field}" must be an array of strings`);
  }
  return [...new Set(value as string[])].sort();
}

function severityMap(value: unknown): Record<string, Severity> {
  if (value === undefined) return {};
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error('Policy field "severity" must be an object');
  }
  const result: Record<string, Severity> = {};
  for (const [id, raw] of Object.entries(value)) {
    if (typeof raw !== "string" || parseSeverity(raw) === undefined) {
      throw new Error(`Invalid severity for ${id}: ${String(raw)}`);
    }
    result[id] = raw as Severity;
  }
  return result;
}

export function normalizePolicy(input: Partial<Policy> = {}): Policy {
  const maxFileBytes = input.maxFileBytes ?? DEFAULT_POLICY.maxFileBytes;
  if (!Number.isSafeInteger(maxFileBytes) || maxFileBytes < 1 || maxFileBytes > 50 * 1024 * 1024) {
    throw new Error("Policy maxFileBytes must be an integer between 1 and 52428800");
  }
  return {
    disabledRules: strings(input.disabledRules, "disabledRules"),
    severity: severityMap(input.severity),
    allowHosts: [...new Set([...(input.allowHosts ?? DEFAULT_POLICY.allowHosts)].map((host) => host.toLowerCase()))].sort(),
    trustedActions: strings(input.trustedActions, "trustedActions"),
    ignorePaths: [...new Set([...(DEFAULT_POLICY.ignorePaths), ...(input.ignorePaths ?? [])])].sort(),
    maxFileBytes,
  };
}

function parseScalar(raw: string): unknown {
  const value = raw.trim().replace(/^(["'])(.*)\1$/, "$2");
  if (value === "[]") return [];
  const inlineList = /^\[(.*)\]$/.exec(value);
  if (inlineList !== null) {
    const body = inlineList[1]?.trim() ?? "";
    return body.length === 0 ? [] : body.split(",").map((item) => parseScalar(item.trim()));
  }
  if (/^-?\d+$/.test(value)) return Number(value);
  if (value === "true") return true;
  if (value === "false") return false;
  return value;
}

// Deliberately small, non-executable YAML subset for HookTripwire policy files.
function parseSimpleYaml(content: string): Record<string, unknown> {
  const root: Record<string, unknown> = {};
  let section: string | undefined;
  for (const [index, source] of content.split(/\r?\n/).entries()) {
    const withoutComment = source.replace(/\s+#.*$/, "");
    if (withoutComment.trim().length === 0 || withoutComment.trim() === "---") continue;
    const indent = withoutComment.length - withoutComment.trimStart().length;
    const trimmed = withoutComment.trim();
    if (indent === 0) {
      const match = /^([A-Za-z][\w-]*):(?:\s*(.*))?$/.exec(trimmed);
      if (!match) throw new Error(`Unsupported YAML syntax on line ${index + 1}`);
      const key = match[1];
      if (key === undefined) throw new Error(`Unsupported YAML key on line ${index + 1}`);
      section = key;
      const rest = match[2] ?? "";
      if (rest.length > 0) {
        root[key] = parseScalar(rest);
        section = undefined;
      } else {
        root[key] = [];
      }
      continue;
    }
    if (section === undefined) throw new Error(`Unexpected YAML indentation on line ${index + 1}`);
    const list = /^-\s+(.+)$/.exec(trimmed);
    if (list) {
      const current = root[section];
      if (!Array.isArray(current)) throw new Error(`Mixed YAML collection on line ${index + 1}`);
      current.push(parseScalar(list[1] ?? ""));
      continue;
    }
    const pair = /^([\w.-]+):\s*(.+)$/.exec(trimmed);
    if (pair) {
      if (Array.isArray(root[section]) && (root[section] as unknown[]).length === 0) root[section] = {};
      const current = root[section];
      if (typeof current !== "object" || current === null || Array.isArray(current)) {
        throw new Error(`Mixed YAML collection on line ${index + 1}`);
      }
      (current as Record<string, unknown>)[pair[1] ?? ""] = parseScalar(pair[2] ?? "");
      continue;
    }
    throw new Error(`Unsupported YAML syntax on line ${index + 1}`);
  }
  return root;
}

export async function loadPolicy(file: string): Promise<Policy> {
  const content = await readFile(file, "utf8");
  let value: unknown;
  try {
    value = path.extname(file).toLowerCase() === ".json" ? JSON.parse(content) : parseSimpleYaml(content);
  } catch (error) {
    throw new Error(`Could not parse policy ${file}: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("Policy must be an object");
  return normalizePolicy(value as Partial<Policy>);
}

export async function loadBaseline(file: string): Promise<Baseline> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(await readFile(file, "utf8"));
  } catch (error) {
    throw new Error(`Could not parse baseline ${file}: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) throw new Error("Baseline must be an object");
  const record = parsed as Record<string, unknown>;
  if (record.version !== 1 || !Array.isArray(record.fingerprints) || record.fingerprints.some((item) => typeof item !== "string")) {
    throw new Error('Baseline requires { "version": 1, "fingerprints": string[] }');
  }
  return { version: 1, fingerprints: [...new Set(record.fingerprints as string[])].sort() };
}

export function createBaseline(fingerprints: readonly string[]): Baseline {
  return { version: 1, fingerprints: [...new Set(fingerprints)].sort() };
}
