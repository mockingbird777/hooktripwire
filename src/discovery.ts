import { lstat, readFile, readdir, realpath } from "node:fs/promises";
import path from "node:path";
import { globMatches, normalizeRelative, toPosix } from "./utils.js";
import type { Policy, ScanInput, SkippedFile } from "./types.js";

const EXTENSIONS = new Set([".json", ".jsonc", ".yaml", ".yml", ".md", ".markdown", ".sh", ".bash", ".zsh", ".toml"]);
const KNOWN_FILES = new Set(["Dockerfile", "Makefile", "Taskfile", "settings", "hooks", "workflow"]);

export interface DiscoveryResult {
  readonly files: readonly ScanInput[];
  readonly skipped: readonly SkippedFile[];
  readonly bytes: number;
}

function ignored(displayPath: string, policy: Policy): boolean {
  return policy.ignorePaths.some((pattern) => globMatches(pattern, displayPath));
}

function candidate(file: string): boolean {
  const base = path.basename(file);
  const lower = base.toLowerCase();
  if (lower.endsWith(".min.js") || lower.endsWith(".map")) return false;
  return EXTENSIONS.has(path.extname(lower)) || KNOWN_FILES.has(base) || /(?:hook|agent|workflow|settings|permission)/i.test(base);
}

export async function discover(targets: readonly string[], cwd: string, policy: Policy): Promise<DiscoveryResult> {
  const root = path.resolve(cwd);
  const found: string[] = [];
  const skipped: SkippedFile[] = [];
  const seen = new Set<string>();

  async function visit(inputPath: string, explicit = false): Promise<void> {
    const absolute = path.resolve(cwd, inputPath);
    let stat;
    try {
      stat = await lstat(absolute);
    } catch (error) {
      const code = error instanceof Error && "code" in error ? String(error.code) : "unknown";
      throw new Error(`Cannot access ${inputPath}: ${code}`);
    }
    const display = normalizeRelative(root, absolute);
    if (ignored(display, policy)) return;
    if (stat.isSymbolicLink()) {
      skipped.push({ path: display, reason: "symbolic link" });
      return;
    }
    if (stat.isDirectory()) {
      const entries = await readdir(absolute, { withFileTypes: true });
      entries.sort((a, b) => a.name.localeCompare(b.name));
      for (const entry of entries) await visit(path.join(absolute, entry.name));
      return;
    }
    if (!stat.isFile() || (!explicit && !candidate(absolute))) return;
    if (stat.size > policy.maxFileBytes) {
      skipped.push({ path: display, reason: `larger than ${policy.maxFileBytes} bytes` });
      return;
    }
    const canonical = await realpath(absolute);
    if (seen.has(canonical)) return;
    seen.add(canonical);
    found.push(absolute);
  }

  for (const target of targets.length > 0 ? targets : ["."]) await visit(target, true);
  found.sort((a, b) => toPosix(a).localeCompare(toPosix(b)));

  const files: ScanInput[] = [];
  let bytes = 0;
  for (const file of found) {
    const buffer = await readFile(file);
    if (buffer.includes(0)) {
      skipped.push({ path: normalizeRelative(root, file), reason: "binary content" });
      continue;
    }
    bytes += buffer.byteLength;
    files.push({ path: file, displayPath: normalizeRelative(root, file), content: buffer.toString("utf8") });
  }
  skipped.sort((a, b) => a.path.localeCompare(b.path));
  return { files, skipped, bytes };
}
