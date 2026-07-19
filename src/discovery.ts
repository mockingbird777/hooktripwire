import { constants } from "node:fs";
import { lstat, open, readdir, realpath } from "node:fs/promises";
import path from "node:path";
import { TextDecoder } from "node:util";
import { compareText, globMatches, normalizeRelative, toPosix } from "./utils.js";
import type { Policy, ScanInput, SkippedFile } from "./types.js";
import type { FileHandle } from "node:fs/promises";

const EXTENSIONS = new Set([".json", ".jsonc", ".yaml", ".yml", ".sh", ".bash", ".zsh", ".toml"]);
const KNOWN_FILES = new Set(["Dockerfile", "Makefile", "Taskfile", "settings", "hooks", "workflow"]);

export interface DiscoveryResult {
  readonly files: readonly ScanInput[];
  readonly skipped: readonly SkippedFile[];
  readonly bytes: number;
}

async function readBounded(handle: FileHandle, limit: number): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let total = 0;
  while (total <= limit) {
    const chunk = Buffer.allocUnsafe(Math.min(64 * 1024, limit + 1 - total));
    const { bytesRead } = await handle.read(chunk, 0, chunk.length, null);
    if (bytesRead === 0) break;
    chunks.push(chunk.subarray(0, bytesRead));
    total += bytesRead;
  }
  return Buffer.concat(chunks, total);
}

function ignored(displayPath: string, policy: Policy): boolean {
  return policy.ignorePaths.some((pattern) => globMatches(pattern, displayPath));
}

function candidate(file: string): boolean {
  const base = path.basename(file);
  const lower = base.toLowerCase();
  const normalized = toPosix(file).toLowerCase();
  if (lower.endsWith(".min.js") || lower.endsWith(".map")) return false;
  if ([".md", ".markdown", ".mdc"].includes(path.extname(lower))) {
    return /(?:^|\/)(?:agents|claude|gemini|copilot-instructions)\.(?:md|markdown)$/.test(normalized)
      || /\/(?:\.claude|\.cursor|\.windsurf|\.roo|\.github\/instructions)\//.test(normalized)
      || /\.instructions\.md$/.test(normalized);
  }
  return EXTENSIONS.has(path.extname(lower)) || KNOWN_FILES.has(base) || /(?:hook|agent|workflow|settings|permission)/i.test(base);
}

export async function discover(targets: readonly string[], cwd: string, policy: Policy): Promise<DiscoveryResult> {
  const root = path.resolve(cwd);
  const found: Array<{ absolute: string; device: number; inode: number }> = [];
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
      entries.sort((a, b) => compareText(a.name, b.name));
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
    found.push({ absolute, device: stat.dev, inode: stat.ino });
  }

  for (const target of targets.length > 0 ? targets : ["."]) await visit(target, true);
  found.sort((a, b) => compareText(toPosix(a.absolute), toPosix(b.absolute)));

  const files: ScanInput[] = [];
  let bytes = 0;
  for (const entry of found) {
    const display = normalizeRelative(root, entry.absolute);
    let handle: FileHandle | undefined;
    try {
      const noFollow = process.platform === "win32" ? 0 : constants.O_NOFOLLOW;
      handle = await open(entry.absolute, constants.O_RDONLY | noFollow);
      const stat = await handle.stat();
      if (!stat.isFile() || stat.dev !== entry.device || stat.ino !== entry.inode) {
        skipped.push({ path: display, reason: "changed during scan" });
        continue;
      }
      if (stat.size > policy.maxFileBytes) {
        skipped.push({ path: display, reason: `larger than ${policy.maxFileBytes} bytes` });
        continue;
      }
      const buffer = await readBounded(handle, policy.maxFileBytes);
      if (buffer.byteLength > policy.maxFileBytes) {
        skipped.push({ path: display, reason: `grew larger than ${policy.maxFileBytes} bytes during scan` });
        continue;
      }
      if (buffer.includes(0)) {
        skipped.push({ path: display, reason: "binary content" });
        continue;
      }
      let content: string;
      try { content = new TextDecoder("utf-8", { fatal: true }).decode(buffer); }
      catch { skipped.push({ path: display, reason: "binary or non-UTF-8 content" }); continue; }
      bytes += buffer.byteLength;
      files.push({ path: entry.absolute, displayPath: display, content });
    } catch (error) {
      const code = error instanceof Error && "code" in error ? String(error.code) : "unknown";
      if (code === "ELOOP" || code === "EMLINK") skipped.push({ path: display, reason: "symbolic link" });
      else throw error;
    } finally {
      await handle?.close();
    }
  }
  skipped.sort((a, b) => compareText(a.path, b.path));
  return { files, skipped, bytes };
}
