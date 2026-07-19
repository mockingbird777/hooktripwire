import path from "node:path";
import { compactEvidence } from "./utils.js";
function hit(meta, context, match, message, severity) {
    const evidence = compactEvidence(match[0]);
    const offset = Math.max(0, match.index ?? context.line.indexOf(match[0]));
    const prefix = context.window.slice(0, offset).split("\n");
    return {
        ruleId: meta.id,
        line: context.index + prefix.length,
        column: (prefix.at(-1)?.length ?? 0) + 1,
        evidence,
        ...(message === undefined ? {} : { message }),
        ...(severity === undefined ? {} : { severity }),
    };
}
function continuedCommand(context) {
    let value = context.line;
    let current = context.line;
    for (let offset = 1; offset < 3 && /\\\s*$/.test(current); offset += 1) {
        current = context.lines[context.index + offset] ?? "";
        value += `\n${current}`;
    }
    return value;
}
function lineRule(meta, expression, message) {
    return {
        meta,
        detect(context) {
            const match = context.line.match(expression);
            return match === null ? undefined : hit(meta, context, match, message);
        },
    };
}
function isShellComment(context) {
    const extension = path.extname(context.input.displayPath).toLowerCase();
    return [".sh", ".bash", ".zsh"].includes(extension) && /^\s*#/.test(context.line);
}
function hostFrom(value) {
    const match = /https?:\/\/([^\s/'"`]+)/i.exec(value);
    if (!match?.[1])
        return undefined;
    try {
        return new URL(`https://${match[1]}`).hostname.toLowerCase();
    }
    catch {
        return match[1].split(":")[0]?.toLowerCase();
    }
}
function hostAllowed(host, policy) {
    return policy.allowHosts.some((allowed) => host === allowed || (allowed.startsWith("*.") && host.endsWith(allowed.slice(1))));
}
const destructive = {
    id: "HG001",
    title: "Destructive command",
    defaultSeverity: "high",
    description: "A hook can irreversibly remove data, rewrite a worktree, or damage the host.",
    remediation: "Replace it with a scoped, recoverable operation and require an explicit human confirmation at the point of use.",
    tags: ["command", "destructive", "filesystem"],
};
const remotePipe = {
    id: "HG002",
    title: "Remote content piped to an interpreter",
    defaultSeverity: "critical",
    description: "Downloaded content is executed before it can be reviewed or integrity-checked.",
    remediation: "Download to a temporary file, verify a pinned checksum or signature, inspect it, then invoke the interpreter explicitly.",
    tags: ["command", "network", "supply-chain"],
};
const exfiltration = {
    id: "HG003",
    title: "Potential secret exfiltration",
    defaultSeverity: "critical",
    description: "A network command appears to transmit a secret-bearing variable or sensitive file.",
    remediation: "Remove secret material from the payload, restrict the destination with an allowlist, and pass only the minimum credential required.",
    tags: ["secrets", "network", "exfiltration"],
};
const openNetwork = {
    id: "HG004",
    title: "Unrestricted network permission",
    defaultSeverity: "high",
    description: "The automation can contact any remote host.",
    remediation: "Deny network access by default and list the exact hosts and protocols the hook needs.",
    tags: ["permission", "network", "least-privilege"],
};
const injection = {
    id: "HG005",
    title: "Shell injection boundary",
    defaultSeverity: "high",
    description: "Untrusted or dynamically expanded input reaches a shell evaluation primitive.",
    remediation: "Pass arguments as an array without a shell, validate inputs, and avoid eval or interpolated `sh -c` commands.",
    tags: ["command", "injection", "input-validation"],
};
const autoApprove = {
    id: "HG006",
    title: "Overbroad auto-approval",
    defaultSeverity: "critical",
    description: "A permission or approval control is disabled or grants every operation.",
    remediation: "Turn approval checks back on and enumerate the smallest set of commands and tools the agent may use.",
    tags: ["permission", "approval", "least-privilege"],
};
const unpinnedAction = {
    id: "HG007",
    title: "Unpinned remote action",
    defaultSeverity: "medium",
    description: "A remote automation action is referenced by a mutable tag or branch.",
    remediation: "Pin the action to a reviewed 40-character commit SHA and use an update bot to propose upgrades.",
    tags: ["supply-chain", "ci", "integrity"],
};
const sensitiveWrite = {
    id: "HG008",
    title: "Sensitive path mutation",
    defaultSeverity: "high",
    description: "A hook writes to credentials, startup configuration, system settings, or another sensitive path.",
    remediation: "Write only inside a dedicated workspace directory and require approval for any host-level configuration change.",
    tags: ["filesystem", "persistence", "least-privilege"],
};
const secretOutput = {
    id: "HG009",
    title: "Secret may be written to logs",
    defaultSeverity: "high",
    description: "Tracing or output commands can expose a credential in logs or model context.",
    remediation: "Disable shell tracing around secrets and redact sensitive variables before producing output.",
    tags: ["secrets", "logging"],
};
const unverifiedArtifact = {
    id: "HG010",
    title: "Downloaded artifact executed without verification",
    defaultSeverity: "high",
    description: "A remote artifact appears to be downloaded and executed without a checksum or signature check.",
    remediation: "Pin the artifact version and verify a trusted SHA-256 digest or cryptographic signature before execution.",
    tags: ["supply-chain", "network", "integrity"],
};
const mutableImage = {
    id: "HG011",
    title: "Mutable container image",
    defaultSeverity: "medium",
    description: "A container image uses `latest`, omits a version, or is not pinned by digest.",
    remediation: "Pin the image with an immutable `@sha256:` digest and automate reviewed digest updates.",
    tags: ["supply-chain", "container", "integrity"],
};
const inheritedEnvironment = {
    id: "HG012",
    title: "Entire environment exposed",
    defaultSeverity: "high",
    description: "The hook inherits or forwards every environment variable, including unrelated credentials.",
    remediation: "Start from an empty environment and pass an explicit list of non-secret variables.",
    tags: ["secrets", "permission", "least-privilege"],
};
const broadFilesystem = {
    id: "HG013",
    title: "Unrestricted filesystem permission",
    defaultSeverity: "critical",
    description: "The agent is allowed to read or write the whole filesystem or home directory.",
    remediation: "Restrict access to the repository and a dedicated temporary directory; make all other paths read-only or denied.",
    tags: ["filesystem", "permission", "least-privilege"],
};
const insecureTls = {
    id: "HG014",
    title: "TLS verification disabled",
    defaultSeverity: "high",
    description: "The command disables certificate verification and can accept a man-in-the-middle response.",
    remediation: "Restore certificate verification and configure a trusted CA explicitly when private infrastructure requires it.",
    tags: ["network", "tls"],
};
const inlineSecret = {
    id: "HG015",
    title: "Hard-coded credential",
    defaultSeverity: "critical",
    description: "Configuration appears to contain a literal credential.",
    remediation: "Revoke the credential, remove it from history, and inject a narrowly scoped secret through the CI or runtime secret store.",
    tags: ["secrets", "credential"],
};
const rules = [
    {
        meta: destructive,
        detect(context) {
            if (isShellComment(context))
                return undefined;
            const match = context.line.match(/\b(?:rm\s+(?:-[A-Za-z]*[rf][A-Za-z]*\s+)+(?:\/|~|\$HOME|\*|\.\.\/)|git\s+(?:reset\s+--hard|clean\s+-[A-Za-z]*f[A-Za-z]*d)|mkfs(?:\.[a-z0-9]+)?\s|dd\s+if=|diskutil\s+(?:erase|partition)|shutdown\s|reboot\s|:\(\)\s*\{)/i);
            return match === null ? undefined : hit(destructive, context, match);
        },
    },
    {
        meta: remotePipe,
        detect(context) {
            if (isShellComment(context))
                return undefined;
            const match = context.window.match(/\b(?:curl|wget)\b[^\n]{0,500}(?:\n[^\n]{0,500}){0,2}?\|\s*(?:sudo\s+)?(?:sh|bash|zsh|fish|node|python\d*|ruby|perl)\b/i);
            return match === null ? undefined : hit(remotePipe, context, match);
        },
    },
    {
        meta: exfiltration,
        detect(context) {
            if (isShellComment(context))
                return undefined;
            const command = continuedCommand(context);
            if (!/\b(?:curl|wget|nc|netcat|Invoke-WebRequest)\b|https?:\/\//i.test(command))
                return undefined;
            if (!/(?:\$(?:\{|\()?(?:[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|CREDENTIAL)[A-Z0-9_]*)|~?\/?(?:\.ssh|\.aws|\.gnupg|\.config\/gh)|\/etc\/(?:shadow|passwd))/i.test(command))
                return undefined;
            const host = hostFrom(command);
            if (host !== undefined && hostAllowed(host, context.policy))
                return undefined;
            const match = command.match(/\b(?:curl|wget|nc|netcat|Invoke-WebRequest)\b[^\n]*(?:\n[^\n]*){0,2}/i) ?? command.match(/https?:\/\/[^\s]+/i);
            return match === null ? undefined : hit(exfiltration, context, match, host === undefined ? undefined : `Sensitive material may be sent to ${host}.`);
        },
    },
    {
        meta: openNetwork,
        detect(context) {
            const match = context.line.match(/\b(?:network(?:Access|Permission|Policy)?|allowedHosts|allowDomains|domains)\b["']?\s*[:=]\s*(?:["']?(?:\*|all|any)["']?|true|\[\s*["']\*["']\s*\])/i);
            return match === null ? undefined : hit(openNetwork, context, match);
        },
    },
    {
        meta: injection,
        detect(context) {
            if (isShellComment(context))
                return undefined;
            const direct = context.line.match(/\beval\s+(?:["']?\$|`)|\b(?:sh|bash|zsh)\s+-c\s+["'][^"']*(?:\$\{|\$[A-Za-z_]|\$\()[^"']*["']/i);
            if (direct !== null)
                return hit(injection, context, direct);
            const workflow = context.line.match(/\brun\s*:\s*.*\$\{\{\s*(?:github\.event|inputs\.|steps\.[^.]+\.outputs)/i);
            return workflow === null ? undefined : hit(injection, context, workflow, "Workflow-controlled data is interpolated directly into a shell step.");
        },
    },
    {
        meta: autoApprove,
        detect(context) {
            const match = context.line.match(/\b(?:dangerouslyDisableSandbox|dangerouslySkipPermissions|disablePermissions?|bypassPermissions?|skipApproval|autoApprove|auto_approve|allowedTools|allow)\b["']?\s*[:=]\s*(?:true|["']?(?:\*|all|any|everything|write-all)["']?|\[\s*["']\*["']\s*\]|["']Bash\(\*\)["'])/i);
            return match === null ? undefined : hit(autoApprove, context, match);
        },
    },
    {
        meta: unpinnedAction,
        detect(context) {
            const match = context.line.match(/\buses\s*:\s*([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.\/-]+)?)@([^\s#"']+)/i);
            if (match === null)
                return undefined;
            const action = match[1] ?? "";
            const ref = match[2] ?? "";
            if (/^[a-f0-9]{40}$/i.test(ref) || context.policy.trustedActions.includes(`${action}@${ref}`) || context.policy.trustedActions.includes(action))
                return undefined;
            return hit(unpinnedAction, context, match, `${action}@${ref} is mutable.`);
        },
    },
    {
        meta: sensitiveWrite,
        detect(context) {
            if (isShellComment(context))
                return undefined;
            const match = context.line.match(/(?:>>?|\btee\b|\b(?:cp|mv|install|chmod|chown|rm|sed\s+-i)\b)[^\n]{0,200}(?:~|\$HOME)?\/?(?:\.ssh(?:\/|\b)|\.aws\/credentials|\.gnupg(?:\/|\b)|\.config\/(?:gh|git)\/|\/etc(?:\/|\b)|\/Library\/Launch(?:Agents|Daemons)|\.bashrc\b|\.zshrc\b)/i);
            return match === null ? undefined : hit(sensitiveWrite, context, match);
        },
    },
    {
        meta: secretOutput,
        detect(context) {
            if (isShellComment(context))
                return undefined;
            const trace = context.line.match(/(?:^|[;&|]\s*)set\s+-x(?:\s|$)/);
            if (trace !== null)
                return hit(secretOutput, context, trace, "Shell tracing can copy later credentials into logs.", "medium");
            const match = context.line.match(/\b(?:echo|printf|printenv|Write-Output)\b[^\n]{0,160}\$(?:\{)?[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|CREDENTIAL)[A-Z0-9_]*(?:\})?/i);
            return match === null ? undefined : hit(secretOutput, context, match);
        },
    },
    {
        meta: unverifiedArtifact,
        detect(context) {
            if (isShellComment(context) || !/\b(?:curl|wget)\b/i.test(context.window))
                return undefined;
            if (/\b(?:curl|wget)\b[^\n]{0,500}(?:\n[^\n]{0,500}){0,2}?\|\s*(?:sudo\s+)?(?:sh|bash|zsh|fish|node|python\d*|ruby|perl)\b/i.test(context.window))
                return undefined;
            if (/\b(?:sha256sum|shasum\s+-a\s+256|cosign\s+verify|gpg\s+--verify|openssl\s+dgst)\b/i.test(context.window))
                return undefined;
            const match = context.window.match(/\b(?:curl|wget)\b[^\n]*(?:\n[^\n]*){0,2}\b(?:chmod\s+\+x|\.\/[A-Za-z0-9_.-]+|exec\s+|(?:sh|bash|node|python)\s+)[^\n]*/i);
            return match === null ? undefined : hit(unverifiedArtifact, context, match);
        },
    },
    {
        meta: mutableImage,
        detect(context) {
            const match = context.line.match(/\b(?:image\s*:\s*|docker\s+(?:run|pull)\s+)([a-z0-9][a-z0-9._/-]*)(?::(latest|edge|main|master))?(?![^\n]*@sha256:)/i);
            if (match === null)
                return undefined;
            const full = match[0];
            const image = match[1] ?? "";
            const explicitMutable = match[2] !== undefined;
            const hasVersion = /:[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(full.trim());
            if (!explicitMutable && hasVersion)
                return undefined;
            if (["node", "python", "ruby", "ubuntu", "alpine"].includes(image) || image.includes("/"))
                return hit(mutableImage, context, match);
            return undefined;
        },
    },
    lineRule(inheritedEnvironment, /\b(?:inheritEnv(?:ironment)?|passEnv(?:ironment)?|forwardEnv(?:ironment)?|environment)\b["']?\s*[:=]\s*(?:true|["']?(?:\*|all)["']?|\[\s*["']\*["']\s*\])/i),
    {
        meta: broadFilesystem,
        detect(context) {
            const match = context.line.match(/\b(?:filesystem|fileSystem|allowedPaths|writePaths|readPaths|allowedDirectories|workspaceAccess)\b["']?\s*[:=]\s*(?:["']?(?:\/|~|\*|\*\*|all|read-write)["']?|\[\s*["'](?:\/|~|\*|\*\*)["']\s*\])/i);
            return match === null ? undefined : hit(broadFilesystem, context, match);
        },
    },
    lineRule(insecureTls, /(?:\b(?:curl|wget)\b[^\n]*(?:\s-k(?:\s|$)|--insecure\b)|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0|GIT_SSL_NO_VERIFY\s*=\s*["']?(?:1|true))/i),
    {
        meta: inlineSecret,
        detect(context) {
            const match = context.line.match(/\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|client[_-]?secret|private[_-]?key)\b["']?\s*[:=]\s*["']([^$<{][^"'\s]{11,})["']/i);
            if (match === null)
                return undefined;
            const value = match[1] ?? "";
            if (/^(?:example|placeholder|changeme|redacted|dummy|test|your[_-])/i.test(value) || /^x+$/.test(value))
                return undefined;
            return hit(inlineSecret, context, match);
        },
    },
];
export const RULES = Object.freeze(rules.map((rule) => Object.freeze(rule.meta)));
export function runRules(input, policy) {
    const lines = input.content.split(/\r?\n/);
    const hits = [];
    const seen = new Set();
    for (let index = 0; index < lines.length; index += 1) {
        const line = lines[index] ?? "";
        const window = lines.slice(index, index + 3).join("\n");
        const context = { input, lines, index, line, window, policy };
        for (const rule of rules) {
            if (policy.disabledRules.includes(rule.meta.id))
                continue;
            const result = rule.detect(context);
            if (result === undefined)
                continue;
            const key = `${result.ruleId}:${result.line}:${result.column}`;
            if (seen.has(key))
                continue;
            seen.add(key);
            hits.push(result);
        }
    }
    return hits;
}
//# sourceMappingURL=rules.js.map