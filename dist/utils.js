import { createHash } from "node:crypto";
import path from "node:path";
import { severities } from "./types.js";
const QUOTED_SECRET_ASSIGNMENT = /(["']?\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|token|password|passwd|secret|client[_-]?secret|private[_-]?key|credential)\b["']?\s*[:=]\s*)(["'])((?:\\.|[^\\\r\n])*?)\2/gi;
const SECRET_ASSIGNMENT = /(["']?\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|token|password|passwd|secret|client[_-]?secret|private[_-]?key|credential)\b["']?\s*[:=]\s*)([^\s,"'`}]+)/gi;
const BEARER = /\b(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}/gi;
const BASIC = /\b(Basic\s+)[A-Za-z0-9+/=]{8,}/gi;
const CREDENTIAL_URL = /(https?:\/\/[^\s:/]+:)([^@\s/]+)(@)/gi;
const PRIVATE_KEY = /-----BEGIN [A-Z ]*PRIVATE KEY-----/g;
const KNOWN_TOKEN = /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,})\b/g;
export function severityRank(severity) {
    return severities.indexOf(severity);
}
export function isAtLeast(actual, threshold) {
    return severityRank(actual) >= severityRank(threshold);
}
export function sha256(value) {
    return createHash("sha256").update(value).digest("hex");
}
export function fingerprint(ruleId, displayPath, line, normalizedEvidence) {
    return sha256(`${ruleId}\0${toPosix(displayPath)}\0${line}\0${normalizedEvidence.trim().replace(/\s+/g, " ")}`).slice(0, 24);
}
export function redact(value) {
    return value
        .replace(QUOTED_SECRET_ASSIGNMENT, (_match, prefix, quote) => `${prefix}${quote}<redacted>${quote}`)
        .replace(SECRET_ASSIGNMENT, "$1<redacted>")
        .replace(BEARER, "$1<redacted>")
        .replace(BASIC, "$1<redacted>")
        .replace(CREDENTIAL_URL, "$1<redacted>$3")
        .replace(PRIVATE_KEY, "-----BEGIN <redacted> PRIVATE KEY-----")
        .replace(KNOWN_TOKEN, "<redacted-token>");
}
export function compactEvidence(value, limit = 240) {
    const compact = visibleControls(redact(value).replace(/\s+/gu, " ").trim());
    return compact.length <= limit ? compact : `${compact.slice(0, Math.max(0, limit - 1))}…`;
}
export function visibleControls(value) {
    return value.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g, (character) => `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`);
}
export function escapeHtml(value) {
    return value
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
}
export function escapeMarkdown(value) {
    return escapeHtml(visibleControls(value))
        .replaceAll("\\", "\\\\")
        .replaceAll("|", "\\|")
        .replace(/([`*_{}[\]()#+.!-])/g, "\\$1")
        .replace(/[\r\n]+/g, " ");
}
export function toPosix(value) {
    return value.split(path.sep).join("/");
}
export function compareText(left, right) {
    return left < right ? -1 : left > right ? 1 : 0;
}
export function normalizeRelative(root, absolute) {
    const relative = path.relative(root, absolute);
    return toPosix(relative.length === 0 ? path.basename(absolute) : relative);
}
export function globMatches(pattern, candidate) {
    const normalizedPattern = toPosix(pattern).replace(/^\.\//, "").replace(/\/\*\*$/, "");
    const normalizedCandidate = toPosix(candidate).replace(/^\.\//, "");
    if (normalizedPattern.length === 0)
        return false;
    let expression = "";
    for (let index = 0; index < normalizedPattern.length; index += 1) {
        const character = normalizedPattern[index] ?? "";
        if (character === "*" && normalizedPattern[index + 1] === "*") {
            if (normalizedPattern[index + 2] === "/") {
                expression += "(?:.*/)?";
                index += 2;
            }
            else {
                expression += ".*";
                index += 1;
            }
        }
        else if (character === "*")
            expression += "[^/]*";
        else if (character === "?")
            expression += "[^/]";
        else
            expression += character.replace(/[.+^${}()|[\]\\]/g, "\\$&");
    }
    const anywhere = !normalizedPattern.includes("/");
    return new RegExp(`${anywhere ? "(?:^|.*/)" : "^"}(?:${expression})(?:/.*)?$`).test(normalizedCandidate);
}
export function sortFindings(findings) {
    return [...findings].sort((a, b) => compareText(a.location.path, b.location.path) ||
        a.location.line - b.location.line ||
        a.location.column - b.location.column ||
        compareText(a.ruleId, b.ruleId) ||
        compareText(a.fingerprint, b.fingerprint));
}
export function lineColumn(content, offset) {
    const prefix = content.slice(0, Math.max(0, offset));
    const lines = prefix.split("\n");
    return { line: lines.length, column: (lines.at(-1)?.length ?? 0) + 1 };
}
export function parseSeverity(value) {
    return severities.includes(value) ? value : undefined;
}
export function safeJson(value) {
    return JSON.stringify(value)
        .replaceAll("<", "\\u003c")
        .replaceAll(">", "\\u003e")
        .replaceAll("&", "\\u0026")
        .replaceAll("\u2028", "\\u2028")
        .replaceAll("\u2029", "\\u2029");
}
//# sourceMappingURL=utils.js.map