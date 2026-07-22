import { lstat, realpath } from "node:fs/promises";
import path from "node:path";
import { safeReadFile } from "./discovery.js";
import { compactEvidence, compareText, globMatches, lineColumn, normalizeRelative, toPosix } from "./utils.js";
const DEFAULT_MAX_HOOK_DEPTH = 8;
const MAX_HOOK_ENTRIES = 512;
const MAX_HOOK_FILES = 512;
const MAX_HOOK_EDGES = 4_096;
const MAX_HOOK_PATHS = 1_000;
const MAX_REFERENCES_PER_SOURCE = 128;
const MAX_COMMAND_BYTES = 16 * 1024;
const MAX_EXTRA_BYTES = 16 * 1024 * 1024;
const MAX_JSON_TOKENS = 100_000;
const MAX_JSON_DEPTH = 64;
function isInside(root, candidate) {
    const relative = path.relative(root, candidate);
    return relative === "" || (!path.isAbsolute(relative) && relative !== ".." && !relative.startsWith(`..${path.sep}`));
}
function knownHookConfig(displayPath) {
    const normalized = toPosix(displayPath).toLowerCase();
    const base = path.basename(normalized, path.extname(normalized));
    return /(?:^|\/)\.github\/hooks\//u.test(normalized)
        || /(?:^|[._-])hooks?(?:$|[._-])/u.test(base);
}
function maskJsonComments(content) {
    const output = content.split("");
    let string = false;
    let escaped = false;
    let lineComment = false;
    let blockComment = false;
    for (let index = 0; index < output.length; index += 1) {
        const character = content[index] ?? "";
        const next = content[index + 1] ?? "";
        if (lineComment) {
            if (character === "\n")
                lineComment = false;
            else
                output[index] = " ";
            continue;
        }
        if (blockComment) {
            if (character === "*" && next === "/") {
                output[index] = " ";
                output[index + 1] = " ";
                index += 1;
                blockComment = false;
            }
            else if (character !== "\n")
                output[index] = " ";
            continue;
        }
        if (string) {
            if (escaped)
                escaped = false;
            else if (character === "\\")
                escaped = true;
            else if (character === '"')
                string = false;
            continue;
        }
        if (character === '"')
            string = true;
        else if (character === "/" && next === "/") {
            output[index] = " ";
            output[index + 1] = " ";
            index += 1;
            lineComment = true;
        }
        else if (character === "/" && next === "*") {
            output[index] = " ";
            output[index + 1] = " ";
            index += 1;
            blockComment = true;
        }
    }
    return output.join("");
}
function tokenizeJsonc(content) {
    const source = maskJsonComments(content);
    const tokens = [];
    for (let index = 0; index < source.length;) {
        const character = source[index] ?? "";
        if (/\s/u.test(character)) {
            index += 1;
            continue;
        }
        if ("{}[]:,".includes(character)) {
            tokens.push({ kind: character, offset: index });
            index += 1;
        }
        else if (character === '"') {
            const start = index;
            index += 1;
            let escaped = false;
            while (index < source.length) {
                const current = source[index] ?? "";
                index += 1;
                if (escaped)
                    escaped = false;
                else if (current === "\\")
                    escaped = true;
                else if (current === '"')
                    break;
            }
            if (source[index - 1] !== '"')
                return undefined;
            try {
                const value = JSON.parse(content.slice(start, index));
                if (typeof value !== "string")
                    return undefined;
                tokens.push({ kind: "string", offset: start + 1, value });
            }
            catch {
                return undefined;
            }
        }
        else {
            const start = index;
            while (index < source.length && !/[\s{}[\]:,]/u.test(source[index] ?? ""))
                index += 1;
            if (index === start)
                return undefined;
            tokens.push({ kind: "other", offset: start });
        }
        if (tokens.length > MAX_JSON_TOKENS)
            return undefined;
    }
    return tokens;
}
function parseJsonc(content) {
    const tokens = tokenizeJsonc(content);
    if (tokens === undefined)
        return undefined;
    let index = 0;
    const parseValue = (depth) => {
        if (depth > MAX_JSON_DEPTH)
            return undefined;
        const token = tokens[index];
        if (token === undefined)
            return undefined;
        if (token.kind === "string") {
            index += 1;
            return { kind: "string", value: token.value ?? "", offset: token.offset };
        }
        if (token.kind === "other") {
            index += 1;
            return { kind: "other", offset: token.offset };
        }
        if (token.kind === "[") {
            index += 1;
            const items = [];
            if (tokens[index]?.kind === "]") {
                index += 1;
                return { kind: "array", items, offset: token.offset };
            }
            while (index < tokens.length) {
                const value = parseValue(depth + 1);
                if (value === undefined)
                    return undefined;
                items.push(value);
                if (tokens[index]?.kind === "]") {
                    index += 1;
                    return { kind: "array", items, offset: token.offset };
                }
                if (tokens[index]?.kind !== ",")
                    return undefined;
                index += 1;
                if (tokens[index]?.kind === "]") {
                    index += 1;
                    return { kind: "array", items, offset: token.offset };
                }
            }
            return undefined;
        }
        if (token.kind === "{") {
            index += 1;
            const entries = [];
            if (tokens[index]?.kind === "}") {
                index += 1;
                return { kind: "object", entries, offset: token.offset };
            }
            while (index < tokens.length) {
                const key = tokens[index];
                if (key?.kind !== "string" || tokens[index + 1]?.kind !== ":")
                    return undefined;
                index += 2;
                const value = parseValue(depth + 1);
                if (value === undefined)
                    return undefined;
                entries.push({ key: key.value ?? "", keyOffset: key.offset, value });
                if (tokens[index]?.kind === "}") {
                    index += 1;
                    return { kind: "object", entries, offset: token.offset };
                }
                if (tokens[index]?.kind !== ",")
                    return undefined;
                index += 1;
                if (tokens[index]?.kind === "}") {
                    index += 1;
                    return { kind: "object", entries, offset: token.offset };
                }
            }
        }
        return undefined;
    };
    const value = parseValue(0);
    return value !== undefined && index === tokens.length ? value : undefined;
}
function jsonCommand(node) {
    if (node.kind === "string")
        return node.value;
    if (node.kind !== "array" || node.items.length === 0 || node.items.some((item) => item.kind !== "string"))
        return undefined;
    return node.items.map((item) => item.value);
}
const GENERIC_HOOK_KEYS = new Set(["command", "hooks", "matcher", "name", "timeout", "timeoutseconds", "type", "version"]);
function boundedHookName(value) {
    return compactEvidence(value === undefined || value.length === 0 ? "hook" : value, 80);
}
function commandBytes(command) {
    return Buffer.byteLength(typeof command === "string" ? command : command.join("\0"), "utf8");
}
function extractJsonEntries(input) {
    const root = parseJsonc(input.content);
    if (root === undefined)
        return [];
    const entries = [];
    const configuredFile = knownHookConfig(input.displayPath);
    const add = (node, hook) => {
        if (entries.length > MAX_HOOK_ENTRIES)
            return;
        const command = jsonCommand(node);
        if (command === undefined)
            return;
        const location = lineColumn(input.content, node.offset);
        entries.push({
            hook: boundedHookName(hook),
            location: { path: input.displayPath, line: location.line, column: location.column },
            command,
            limited: commandBytes(command) > MAX_COMMAND_BYTES,
        });
    };
    const visit = (node, inHooks, hook) => {
        if (entries.length > MAX_HOOK_ENTRIES)
            return;
        if (node.kind === "array") {
            for (const item of node.items)
                visit(item, inHooks, hook);
            return;
        }
        if (node.kind !== "object")
            return;
        const typeEntry = [...node.entries].reverse().find((entry) => entry.key.toLowerCase() === "type");
        const typeValue = typeEntry?.value.kind === "string" ? typeEntry.value.value.toLowerCase() : undefined;
        const commandAllowed = typeValue === undefined || typeValue === "command" || typeValue === "shell";
        for (const entry of node.entries) {
            const key = entry.key.toLowerCase();
            if (key === "hooks") {
                visit(entry.value, true, hook);
                continue;
            }
            const eventKey = !GENERIC_HOOK_KEYS.has(key) ? entry.key : undefined;
            const nextHook = inHooks && hook === undefined && eventKey !== undefined ? eventKey : hook;
            if (inHooks && key === "command" && commandAllowed)
                add(entry.value, nextHook);
            else if (inHooks && hook === undefined && eventKey !== undefined && jsonCommand(entry.value) !== undefined)
                add(entry.value, eventKey);
            visit(entry.value, inHooks, nextHook);
        }
    };
    const declaresHooks = root.kind === "object" && root.entries.some((entry) => entry.key.toLowerCase() === "hooks");
    visit(root, configuredFile && !declaresHooks, undefined);
    return entries;
}
function stripYamlComment(line) {
    let quote;
    let escaped = false;
    for (let index = 0; index < line.length; index += 1) {
        const character = line[index] ?? "";
        if (quote !== undefined) {
            if (escaped)
                escaped = false;
            else if (character === "\\" && quote === '"')
                escaped = true;
            else if (character === quote)
                quote = undefined;
        }
        else if (character === '"' || character === "'")
            quote = character;
        else if (character === "#" && (index === 0 || /\s/u.test(line[index - 1] ?? "")))
            return line.slice(0, index);
    }
    return line;
}
function yamlScalar(raw) {
    const value = raw.trim();
    if (value.length === 0 || /^[&*!{}[\]]/u.test(value))
        return undefined;
    if (value.startsWith('"')) {
        try {
            const parsed = JSON.parse(value);
            return typeof parsed === "string" ? parsed : undefined;
        }
        catch {
            return undefined;
        }
    }
    if (value.startsWith("'")) {
        if (!value.endsWith("'") || value.length < 2)
            return undefined;
        return value.slice(1, -1).replaceAll("''", "'");
    }
    return value;
}
function extractYamlEntries(input) {
    const lines = input.content.split(/\r?\n/u);
    const stack = [];
    const entries = [];
    const configuredFile = knownHookConfig(input.displayPath);
    for (let index = 0; index < lines.length; index += 1) {
        const entryLine = index;
        const original = lines[index] ?? "";
        if (/^\s*\t/u.test(original))
            continue;
        const uncommented = stripYamlComment(original);
        if (uncommented.trim().length === 0 || uncommented.trim() === "---")
            continue;
        const indent = uncommented.length - uncommented.trimStart().length;
        const match = /^\s*(?:-\s*)?([A-Za-z0-9_.-]+)\s*:\s*(.*)$/u.exec(uncommented);
        if (match === null)
            continue;
        while (stack.length > 0 && (stack.at(-1)?.indent ?? -1) >= indent)
            stack.pop();
        const key = match[1] ?? "";
        const keyLower = key.toLowerCase();
        const ancestors = stack.map((item) => item.key.toLowerCase());
        const hookIndex = ancestors.indexOf("hooks");
        const inHooks = configuredFile || hookIndex >= 0;
        const hook = hookIndex >= 0
            ? [...stack.slice(hookIndex + 1)].reverse().find((item) => !GENERIC_HOOK_KEYS.has(item.key.toLowerCase()))?.key
            : undefined;
        let rawValue = match[2] ?? "";
        const block = /^[|>][+-]?\d?\s*$/u.exec(rawValue);
        if (block !== null) {
            const folded = rawValue.trimStart().startsWith(">");
            const blockLines = [];
            let next = index + 1;
            let minimumIndent = Number.POSITIVE_INFINITY;
            while (next < lines.length) {
                const candidate = lines[next] ?? "";
                if (candidate.trim().length === 0) {
                    blockLines.push("");
                    next += 1;
                    continue;
                }
                const candidateIndent = candidate.length - candidate.trimStart().length;
                if (candidateIndent <= indent)
                    break;
                minimumIndent = Math.min(minimumIndent, candidateIndent);
                blockLines.push(candidate);
                next += 1;
            }
            const strip = Number.isFinite(minimumIndent) ? minimumIndent : indent + 1;
            rawValue = blockLines.map((line) => line.slice(Math.min(strip, line.length))).join(folded ? " " : "\n");
            index = next - 1;
        }
        const value = yamlScalar(rawValue);
        const directEvent = inHooks
            && keyLower !== "command"
            && !GENERIC_HOOK_KEYS.has(keyLower)
            && value !== undefined
            && (hookIndex === stack.length - 1 || (configuredFile && stack.length === 0));
        if (value !== undefined && ((inHooks && keyLower === "command") || directEvent)) {
            if (entries.length > MAX_HOOK_ENTRIES)
                break;
            const column = Math.max(1, original.indexOf(match[2] ?? "") + 1);
            entries.push({
                hook: boundedHookName(directEvent ? key : hook),
                location: { path: input.displayPath, line: entryLine + 1, column },
                command: value,
                limited: Buffer.byteLength(value, "utf8") > MAX_COMMAND_BYTES,
            });
        }
        if (rawValue.trim().length === 0)
            stack.push({ indent, key });
    }
    return entries;
}
function extractHookEntries(files) {
    const entries = [];
    for (const input of files) {
        if (entries.length >= MAX_HOOK_ENTRIES + 1)
            break;
        const extension = path.extname(input.displayPath).toLowerCase();
        const extracted = extension === ".json" || extension === ".jsonc"
            ? extractJsonEntries(input)
            : extension === ".yaml" || extension === ".yml"
                ? extractYamlEntries(input)
                : [];
        entries.push(...extracted.slice(0, MAX_HOOK_ENTRIES + 1 - entries.length));
    }
    return entries.sort((left, right) => compareText(left.location.path, right.location.path)
        || left.location.line - right.location.line
        || left.location.column - right.location.column
        || compareText(left.hook, right.hook));
}
function shellSegments(command) {
    const segments = [[]];
    let value = "";
    let offset = 0;
    let dynamic = false;
    let quote;
    let escaped = false;
    const push = () => {
        if (value.length === 0)
            return;
        if (/^%[^%\s]+%$/u.test(value))
            dynamic = true;
        segments.at(-1).push({ value, offset, dynamic });
        value = "";
        dynamic = false;
    };
    const split = () => {
        push();
        if ((segments.at(-1)?.length ?? 0) > 0)
            segments.push([]);
    };
    for (let index = 0; index < command.length; index += 1) {
        const character = command[index] ?? "";
        if (escaped) {
            if (character !== "\n")
                value += character;
            escaped = false;
            continue;
        }
        if (quote === "'") {
            if (character === "'")
                quote = undefined;
            else
                value += character;
            continue;
        }
        if (quote === '"') {
            if (character === '"')
                quote = undefined;
            else if (character === "\\")
                escaped = true;
            else {
                if (character === "$" || character === "`")
                    dynamic = true;
                value += character;
            }
            continue;
        }
        if (character === "\\") {
            if (value.length === 0)
                offset = index;
            escaped = true;
            continue;
        }
        if (character === '"' || character === "'") {
            if (value.length === 0)
                offset = index;
            quote = character;
            continue;
        }
        if (character === "#" && value.length === 0) {
            push();
            while (index < command.length && command[index] !== "\n")
                index += 1;
            split();
            continue;
        }
        if (/\s/u.test(character)) {
            push();
            if (character === "\n")
                split();
            continue;
        }
        if (character === ";" || character === "|" || character === "&") {
            split();
            continue;
        }
        if (value.length === 0)
            offset = index;
        if (character === "$" || character === "`" || character === "*" || character === "?" || character === "[" || character === "{")
            dynamic = true;
        if (character === "~" && value.length === 0)
            dynamic = true;
        value += character;
    }
    if (quote !== undefined || escaped)
        dynamic = true;
    push();
    return segments.filter((segment) => segment.length > 0);
}
function launcherName(value) {
    const base = path.posix.basename(value.replaceAll("\\", "/")).toLowerCase();
    if (base === "sh" || base === "bash" || base === "zsh" || base === "node")
        return base;
    if (/^python(?:3(?:\.\d+)?)?$/u.test(base))
        return "python";
    if (base === "source" || base === ".")
        return "source";
    return undefined;
}
function referenceForToken(token, launcher, direct) {
    if (token.dynamic)
        return { launcher, offset: token.offset, incomplete: "dynamic-reference" };
    const value = token.value.trim();
    if (value.length === 0)
        return undefined;
    if (/^[A-Za-z][A-Za-z0-9+.-]*:\/\//u.test(value) || value.startsWith("file:") || value.includes("\0") || path.win32.isAbsolute(value)) {
        return { launcher, offset: token.offset, incomplete: "non-local-reference" };
    }
    if (direct && !value.startsWith(".") && !value.startsWith("/") && !value.includes("/") && !value.includes("\\"))
        return undefined;
    return { launcher, offset: token.offset, value };
}
function referencesFromTokens(tokens) {
    let index = 0;
    while (index < tokens.length && /^[A-Za-z_][A-Za-z0-9_]*=/u.test(tokens[index]?.value ?? ""))
        index += 1;
    if ((tokens[index]?.value ?? "").toLowerCase() === "exec")
        index += 1;
    const executable = tokens[index];
    if (executable === undefined)
        return [];
    const launcher = launcherName(executable.value);
    if (launcher === undefined) {
        const direct = referenceForToken(executable, "direct", true);
        return direct === undefined ? [] : [direct];
    }
    index += 1;
    if (launcher === "source") {
        const target = tokens[index];
        if (target === undefined)
            return [];
        return [referenceForToken(target, launcher, false)].filter((item) => item !== undefined);
    }
    while (tokens[index]?.value === "--")
        index += 1;
    while (/^[-+]/u.test(tokens[index]?.value ?? "")) {
        const option = tokens[index]?.value ?? "";
        const optionName = option.replace(/^[-+]+/u, "");
        // Node.js and Python options have runtime- and version-specific argument
        // semantics (-m, -c, -W, -X, loaders, eval modes, and more). Treat every
        // such invocation as opaque rather than mislabeling an option argument as
        // a repository-local script.
        const dynamicMode = launcher === "node"
            || launcher === "python"
            || optionName.length === 0
            || (!option.startsWith("--") && /[cs]/u.test(optionName))
            || /^--(?:init-file|rcfile)(?:=|$)/u.test(option);
        if (dynamicMode)
            return [{ launcher, offset: tokens[index]?.offset ?? executable.offset, incomplete: "dynamic-reference" }];
        index += !option.startsWith("--") && /[oO]/u.test(optionName) ? 2 : 1;
    }
    const target = tokens[index];
    if (target === undefined)
        return [];
    return [referenceForToken(target, launcher, false)].filter((item) => item !== undefined);
}
function commandReferences(command) {
    if (typeof command !== "string") {
        const tokens = command.map((value, index) => ({ value, offset: index, dynamic: /[$`*?\[{]/u.test(value) || value.startsWith("~") }));
        return referencesFromTokens(tokens);
    }
    return shellSegments(command).flatMap((segment) => referencesFromTokens(segment));
}
function locatedReferences(input, forceShell = false) {
    const extension = path.extname(input.displayPath).toLowerCase();
    const shellLike = forceShell
        || [".sh", ".bash", ".zsh"].includes(extension)
        || /^#![^\n]*\b(?:ba|z)?sh\b/u.test(input.content);
    if (!shellLike)
        return { references: [] };
    const lines = input.content.split(/\r?\n/u);
    const references = [];
    let heredoc;
    for (let index = 0; index < lines.length; index += 1) {
        const startLine = index;
        const source = lines[index] ?? "";
        if (heredoc !== undefined) {
            if (source.trim() === heredoc)
                heredoc = undefined;
            continue;
        }
        let logical = source;
        while (/\\\s*$/u.test(logical) && index + 1 < lines.length) {
            logical = logical.replace(/\\\s*$/u, " ") + (lines[index + 1] ?? "");
            index += 1;
        }
        if (Buffer.byteLength(logical, "utf8") > MAX_COMMAND_BYTES) {
            return { references, incomplete: "command-limit" };
        }
        for (const reference of commandReferences(logical)) {
            references.push({
                ...reference,
                location: { path: input.displayPath, line: startLine + 1, column: reference.offset + 1 },
            });
            if (references.length >= MAX_REFERENCES_PER_SOURCE)
                return { references, incomplete: "edge-limit" };
        }
        const marker = /<<-?\s*['"]?([A-Za-z_][A-Za-z0-9_]*)['"]?/u.exec(logical);
        if (marker !== null)
            heredoc = marker[1];
    }
    references.sort((left, right) => left.location.line - right.location.line
        || left.location.column - right.location.column
        || compareText(left.value ?? left.incomplete ?? "", right.value ?? right.incomplete ?? ""));
    return { references };
}
function edgeKey(edge) {
    return `${edge.from.path}\0${edge.from.line}\0${edge.from.column}\0${edge.launcher}\0${edge.reference}\0${edge.to ?? ""}`;
}
function pathKey(value) {
    return `${value.entry.path}\0${value.entry.line}\0${value.entry.column}\0${value.hook}\0${value.edges.map(edgeKey).join("\u0001")}\0${value.leaf ?? ""}\0${value.incomplete ?? ""}`;
}
function compareHookPaths(left, right) {
    return compareText(left.entry.path, right.entry.path)
        || left.entry.line - right.entry.line
        || left.entry.column - right.entry.column
        || compareText(left.hook, right.hook)
        || compareText(pathKey(left), pathKey(right));
}
function incompletePath(entry, edges, reason, leaf) {
    return {
        entry: entry.location,
        hook: entry.hook,
        edges,
        findingFingerprints: [],
        incomplete: reason,
        ...(leaf === undefined ? {} : { leaf }),
    };
}
export function validateMaxHookDepth(value) {
    const depth = value ?? DEFAULT_MAX_HOOK_DEPTH;
    if (!Number.isSafeInteger(depth) || depth < 1 || depth > 32)
        throw new Error("maxHookDepth must be an integer from 1 to 32");
    return depth;
}
export async function mapHookPaths(initialFiles, cwd, policy, requestedDepth) {
    const maxDepth = validateMaxHookDepth(requestedDepth);
    const root = path.resolve(cwd);
    const canonicalRoot = await realpath(root);
    const entries = extractHookEntries(initialFiles);
    const initialByAbsolute = new Map(initialFiles.map((input) => [path.resolve(input.path), input]));
    const readCache = new Map();
    const extraFiles = new Map();
    const skipped = new Map();
    const paths = [];
    let extraBytes = 0;
    let mappedFiles = 0;
    let traversedEdges = 0;
    let stopped = false;
    const appendPath = (candidate) => {
        if (stopped)
            return false;
        if (paths.length < MAX_HOOK_PATHS - 1) {
            paths.push(candidate);
            return true;
        }
        paths.push(incompletePath({ hook: candidate.hook, location: candidate.entry, command: "", limited: false }, candidate.edges, "path-limit", candidate.leaf));
        stopped = true;
        return false;
    };
    const readReference = async (reference) => {
        if (reference.includes("\0") || /^[A-Za-z][A-Za-z0-9+.-]*:\/\//u.test(reference) || reference.startsWith("file:") || path.win32.isAbsolute(reference)) {
            return { reason: "non-local-reference" };
        }
        const absolute = path.isAbsolute(reference) ? path.normalize(reference) : path.resolve(root, reference);
        if (!isInside(root, absolute))
            return { reason: "outside-root" };
        const cached = readCache.get(absolute);
        if (cached !== undefined)
            return cached;
        const displayPath = normalizeRelative(root, absolute);
        if (policy.ignorePaths.some((pattern) => globMatches(pattern, displayPath))) {
            const outcome = { reason: "ignored" };
            readCache.set(absolute, outcome);
            return outcome;
        }
        let cursor = root;
        let finalStat;
        try {
            const relative = path.relative(root, absolute);
            for (const component of relative.split(path.sep).filter((item) => item.length > 0)) {
                cursor = path.join(cursor, component);
                const stat = await lstat(cursor);
                if (stat.isSymbolicLink()) {
                    const item = { path: toPosix(path.relative(root, cursor)), reason: "symbolic link" };
                    const outcome = { reason: "symbolic-link", skipped: item };
                    skipped.set(`${item.path}\0${item.reason}`, item);
                    readCache.set(absolute, outcome);
                    return outcome;
                }
                finalStat = stat;
            }
        }
        catch (error) {
            const code = error instanceof Error && "code" in error ? String(error.code) : "unknown";
            const outcome = { reason: code === "ENOENT" ? "missing-file" : "unreadable" };
            readCache.set(absolute, outcome);
            return outcome;
        }
        if (finalStat === undefined || !finalStat.isFile()) {
            const outcome = { reason: "unreadable" };
            readCache.set(absolute, outcome);
            return outcome;
        }
        let canonical;
        try {
            canonical = await realpath(absolute);
        }
        catch {
            const outcome = { reason: "unreadable" };
            readCache.set(absolute, outcome);
            return outcome;
        }
        if (!isInside(canonicalRoot, canonical)) {
            const outcome = { reason: "outside-root" };
            readCache.set(absolute, outcome);
            return outcome;
        }
        const initial = initialByAbsolute.get(absolute);
        if (initial !== undefined) {
            const outcome = { input: initial, absolute, canonical, displayPath: initial.displayPath };
            readCache.set(absolute, outcome);
            return outcome;
        }
        if (mappedFiles >= MAX_HOOK_FILES) {
            const outcome = { reason: "file-limit" };
            readCache.set(absolute, outcome);
            return outcome;
        }
        if (extraBytes + finalStat.size > MAX_EXTRA_BYTES) {
            const outcome = { reason: "read-limit" };
            readCache.set(absolute, outcome);
            return outcome;
        }
        try {
            const read = await safeReadFile(absolute, displayPath, policy, { device: finalStat.dev, inode: finalStat.ino });
            if (read.input === undefined) {
                const item = read.skipped;
                if (item !== undefined)
                    skipped.set(`${item.path}\0${item.reason}`, item);
                const outcome = { reason: item?.reason === "symbolic link" ? "symbolic-link" : "unreadable", ...(item === undefined ? {} : { skipped: item }) };
                readCache.set(absolute, outcome);
                return outcome;
            }
            mappedFiles += 1;
            extraBytes += read.bytes;
            extraFiles.set(absolute, read.input);
            const outcome = { input: read.input, absolute, canonical, displayPath };
            readCache.set(absolute, outcome);
            return outcome;
        }
        catch {
            const outcome = { reason: "unreadable" };
            readCache.set(absolute, outcome);
            return outcome;
        }
    };
    const walk = async (entry, reference, priorEdges, visited, depth) => {
        if (stopped)
            return;
        if (traversedEdges >= MAX_HOOK_EDGES) {
            appendPath(incompletePath(entry, priorEdges, "edge-limit", priorEdges.at(-1)?.to));
            stopped = true;
            return;
        }
        traversedEdges += 1;
        if (reference.incomplete !== undefined || reference.value === undefined) {
            const edge = {
                from: reference.location,
                launcher: reference.launcher,
                reference: reference.incomplete === "non-local-reference" ? "<non-local>" : "<dynamic>",
            };
            appendPath(incompletePath(entry, [...priorEdges, edge], reference.incomplete ?? "dynamic-reference", priorEdges.at(-1)?.to));
            return;
        }
        const resolved = await readReference(reference.value);
        if ("reason" in resolved) {
            const edge = {
                from: reference.location,
                launcher: reference.launcher,
                reference: compactEvidence(reference.value, 160),
            };
            appendPath(incompletePath(entry, [...priorEdges, edge], resolved.reason, priorEdges.at(-1)?.to));
            return;
        }
        const edge = {
            from: reference.location,
            launcher: reference.launcher,
            reference: resolved.displayPath,
            to: resolved.displayPath,
        };
        const nextEdges = [...priorEdges, edge];
        if (visited.has(resolved.canonical)) {
            appendPath(incompletePath(entry, nextEdges, "cycle", resolved.displayPath));
            return;
        }
        const extracted = locatedReferences(resolved.input, reference.launcher === "sh" || reference.launcher === "bash" || reference.launcher === "zsh" || reference.launcher === "source");
        if (extracted.references.length === 0 && extracted.incomplete !== undefined) {
            appendPath(incompletePath(entry, nextEdges, extracted.incomplete, resolved.displayPath));
            return;
        }
        if (extracted.references.length === 0) {
            appendPath({ entry: entry.location, hook: entry.hook, edges: nextEdges, leaf: resolved.displayPath, findingFingerprints: [] });
            return;
        }
        if (depth >= maxDepth) {
            appendPath(incompletePath(entry, nextEdges, "depth-limit", resolved.displayPath));
            return;
        }
        const nextVisited = new Set(visited);
        nextVisited.add(resolved.canonical);
        for (const child of extracted.references)
            await walk(entry, child, nextEdges, nextVisited, depth + 1);
        if (extracted.incomplete !== undefined)
            appendPath(incompletePath(entry, nextEdges, extracted.incomplete, resolved.displayPath));
    };
    const selectedEntries = entries.slice(0, MAX_HOOK_ENTRIES);
    for (const entry of selectedEntries) {
        if (stopped)
            break;
        if (entry.limited) {
            appendPath(incompletePath(entry, [], "command-limit"));
            continue;
        }
        const allReferences = commandReferences(entry.command)
            .map((reference) => ({ ...reference, location: entry.location }));
        for (const reference of allReferences.slice(0, MAX_REFERENCES_PER_SOURCE))
            await walk(entry, reference, [], new Set(), 1);
        if (!stopped && allReferences.length > MAX_REFERENCES_PER_SOURCE)
            appendPath(incompletePath(entry, [], "edge-limit"));
    }
    if (!stopped && entries.length > selectedEntries.length) {
        const omitted = entries[selectedEntries.length];
        appendPath(incompletePath(omitted, [], "path-limit"));
    }
    const unique = new Map();
    for (const item of paths)
        unique.set(pathKey(item), item);
    return {
        files: [...extraFiles.values()].sort((left, right) => compareText(left.displayPath, right.displayPath)),
        bytes: extraBytes,
        skipped: [...skipped.values()].sort((left, right) => compareText(left.path, right.path) || compareText(left.reason, right.reason)),
        paths: [...unique.values()].sort(compareHookPaths),
    };
}
export function attachHookPathFindings(paths, findings) {
    const byPath = new Map();
    for (const finding of findings) {
        const fingerprints = byPath.get(finding.location.path) ?? [];
        fingerprints.push(finding.fingerprint);
        byPath.set(finding.location.path, fingerprints);
    }
    return paths.map((item) => ({
        ...item,
        findingFingerprints: [...new Set(item.leaf === undefined ? [] : byPath.get(item.leaf) ?? [])].sort(compareText),
    }));
}
//# sourceMappingURL=hookgraph.js.map