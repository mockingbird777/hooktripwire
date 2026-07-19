import { createHash } from "node:crypto";
import path from "node:path";
import { severities } from "./types.js";
const SECRET_ASSIGNMENT = /\b(api[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|client[_-]?secret|private[_-]?key)\b\s*[:=]\s*(["']?)([^\s,"'`}]+)/gi;
const BEARER = /\b(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}/gi;
const CREDENTIAL_URL = /(https?:\/\/[^\s:/]+:)([^@\s/]+)(@)/gi;
const PRIVATE_KEY = /-----BEGIN [A-Z ]*PRIVATE KEY-----/g;
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
        .replace(SECRET_ASSIGNMENT, (_match, name, quote) => `${name}=${quote || ""}<redacted>`)
        .replace(BEARER, "$1<redacted>")
        .replace(CREDENTIAL_URL, "$1<redacted>$3")
        .replace(PRIVATE_KEY, "-----BEGIN <redacted> PRIVATE KEY-----");
}
export function compactEvidence(value, limit = 240) {
    const compact = redact(value.replace(/[\t\r]+/g, " ").trim()).replace(/\s{2,}/g, " ");
    return compact.length <= limit ? compact : `${compact.slice(0, Math.max(0, limit - 1))}…`;
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
    return value.replaceAll("\\", "\\\\").replaceAll("|", "\\|").replaceAll("\n", " ");
}
export function toPosix(value) {
    return value.split(path.sep).join("/");
}
export function normalizeRelative(root, absolute) {
    const relative = path.relative(root, absolute);
    return toPosix(relative.length === 0 ? path.basename(absolute) : relative);
}
export function globMatches(pattern, candidate) {
    const normalizedPattern = toPosix(pattern).replace(/^\.\//, "");
    const normalizedCandidate = toPosix(candidate).replace(/^\.\//, "");
    if (normalizedPattern.endsWith("/**") && normalizedCandidate === normalizedPattern.slice(0, -3))
        return true;
    const escaped = normalizedPattern.replace(/[.+^${}()|[\]\\]/g, "\\$&");
    const regex = escaped.replaceAll("**", "\0").replaceAll("*", "[^/]*").replaceAll("?", "[^/]").replaceAll("\0", ".*");
    return new RegExp(`^(?:${regex})(?:/.*)?$`).test(normalizedCandidate);
}
export function sortFindings(findings) {
    return [...findings].sort((a, b) => a.location.path.localeCompare(b.location.path) ||
        a.location.line - b.location.line ||
        a.location.column - b.location.column ||
        a.ruleId.localeCompare(b.ruleId) ||
        a.fingerprint.localeCompare(b.fingerprint));
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
    return JSON.stringify(value).replaceAll("<", "\\u003c").replaceAll(">", "\\u003e").replaceAll("&", "\\u0026");
}
//# sourceMappingURL=utils.js.map