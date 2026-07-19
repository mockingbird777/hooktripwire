import path from "node:path";
import { compactEvidence } from "./utils.js";
import type { Policy, RuleMetadata, ScanInput, Severity } from "./types.js";

export interface RuleHit {
  readonly ruleId: string;
  readonly line: number;
  readonly column: number;
  readonly evidence: string;
  readonly message?: string;
  readonly severity?: Severity;
}

interface LineContext {
  readonly input: ScanInput;
  readonly lines: readonly string[];
  readonly index: number;
  readonly line: string;
  readonly window: string;
  readonly originalWindow: string;
  readonly policy: Policy;
}

interface Rule {
  readonly meta: RuleMetadata;
  readonly detect: (context: LineContext) => RuleHit | undefined;
}

function hit(meta: RuleMetadata, context: LineContext, match: RegExpMatchArray, message?: string, severity?: Severity): RuleHit {
  const offset = Math.max(0, match.index ?? context.line.indexOf(match[0]));
  const evidence = compactEvidence(context.originalWindow.slice(offset, offset + match[0].length));
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

function throughLine(context: LineContext, match: RegExpMatchArray): RegExpMatchArray {
  const offset = Math.max(0, match.index ?? context.line.indexOf(match[0]));
  const expanded = /^[^\n]*/.exec(context.line.slice(offset));
  return expanded === null ? match : Object.assign(expanded, { index: offset });
}

function continuedCommand(context: LineContext): string {
  let value = context.line;
  let current = context.line;
  for (let offset = 1; offset < 3 && /\\\s*$/.test(current); offset += 1) {
    current = context.lines[context.index + offset] ?? "";
    value += `\n${current}`;
  }
  return value;
}

function maskSlashComments(content: string): string {
  const output = content.split("");
  let quote: "\"" | "'" | undefined;
  let escaped = false;
  let lineComment = false;
  let blockComment = false;
  for (let index = 0; index < output.length; index += 1) {
    const character = content[index] ?? "";
    const next = content[index + 1] ?? "";
    if (lineComment) {
      if (character === "\n") lineComment = false;
      else output[index] = " ";
      continue;
    }
    if (blockComment) {
      if (character === "*" && next === "/") {
        output[index] = " "; output[index + 1] = " "; index += 1; blockComment = false;
      } else if (character !== "\n") output[index] = " ";
      continue;
    }
    if (quote !== undefined) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === quote) quote = undefined;
      continue;
    }
    if (character === "\"" || character === "'") { quote = character; continue; }
    if (character === "/" && next === "/") {
      output[index] = " "; output[index + 1] = " "; index += 1; lineComment = true;
    } else if (character === "/" && next === "*") {
      output[index] = " "; output[index + 1] = " "; index += 1; blockComment = true;
    }
  }
  return output.join("");
}

function maskHashComments(content: string): string {
  return content.split("\n").map((line) => {
    let quote: "\"" | "'" | undefined;
    let escaped = false;
    for (let index = 0; index < line.length; index += 1) {
      const character = line[index] ?? "";
      if (quote !== undefined) {
        if (escaped) escaped = false;
        else if (character === "\\" && quote === "\"") escaped = true;
        else if (character === quote) quote = undefined;
        continue;
      }
      if (character === "\"" || character === "'") { quote = character; continue; }
      if (character === "#" && (index === 0 || /\s/.test(line[index - 1] ?? ""))) return `${line.slice(0, index)}${" ".repeat(line.length - index)}`;
    }
    return line;
  }).join("\n");
}

function maskHtmlComments(content: string): string {
  const output = content.split("");
  let inside = false;
  for (let index = 0; index < output.length; index += 1) {
    if (!inside && content.slice(index, index + 4) === "<!--") inside = true;
    if (inside && content[index] !== "\n") output[index] = " ";
    if (inside && content.slice(index, index + 3) === "-->") {
      output[index] = " "; output[index + 1] = " "; output[index + 2] = " "; index += 2; inside = false;
    }
  }
  return output.join("");
}

function maskedContent(input: ScanInput): string {
  const extension = path.extname(input.displayPath).toLowerCase();
  const base = path.basename(input.displayPath).toLowerCase();
  if ([".json", ".jsonc"].includes(extension) || (extension === "" && /^[\s\uFEFF]*[\[{]/.test(input.content))) return maskSlashComments(input.content);
  if ([".md", ".markdown"].includes(extension)) return maskHtmlComments(input.content);
  if ([".yaml", ".yml", ".toml", ".sh", ".bash", ".zsh"].includes(extension) || ["dockerfile", "makefile", "taskfile"].includes(base)) return maskHashComments(input.content);
  return input.content;
}

function hostsFrom(value: string): string[] {
  const hosts: string[] = [];
  for (const match of value.matchAll(/https?:\/\/[^\s'"`]+/gi)) {
    try {
      hosts.push(new URL(match[0]).hostname.toLowerCase());
    } catch {
      // A malformed URL is still detected by the surrounding network heuristic.
    }
  }
  return [...new Set(hosts)];
}

function hostAllowed(host: string, policy: Policy): boolean {
  return policy.allowHosts.some((allowed) => host === allowed || (allowed.startsWith("*.") && host.endsWith(allowed.slice(1))));
}

const destructive: RuleMetadata = {
  id: "HG001",
  title: "Destructive command",
  defaultSeverity: "high",
  description: "A hook can irreversibly remove data, rewrite a worktree, or damage the host.",
  remediation: "Replace it with a scoped, recoverable operation and require an explicit human confirmation at the point of use.",
  tags: ["command", "destructive", "filesystem"],
};

const remotePipe: RuleMetadata = {
  id: "HG002",
  title: "Remote content piped to an interpreter",
  defaultSeverity: "critical",
  description: "Downloaded content is executed before it can be reviewed or integrity-checked.",
  remediation: "Download to a temporary file, verify a pinned checksum or signature, inspect it, then invoke the interpreter explicitly.",
  tags: ["command", "network", "supply-chain"],
};

const exfiltration: RuleMetadata = {
  id: "HG003",
  title: "Potential secret exfiltration",
  defaultSeverity: "critical",
  description: "A network command appears to transmit a secret-bearing variable or sensitive file.",
  remediation: "Remove secret material from the payload, restrict the destination with an allowlist, and pass only the minimum credential required.",
  tags: ["secrets", "network", "exfiltration"],
};

const openNetwork: RuleMetadata = {
  id: "HG004",
  title: "Unrestricted network permission",
  defaultSeverity: "high",
  description: "The automation can contact any remote host.",
  remediation: "Deny network access by default and list the exact hosts and protocols the hook needs.",
  tags: ["permission", "network", "least-privilege"],
};

const injection: RuleMetadata = {
  id: "HG005",
  title: "Shell injection boundary",
  defaultSeverity: "high",
  description: "Untrusted or dynamically expanded input reaches a shell evaluation primitive.",
  remediation: "Pass arguments as an array without a shell, validate inputs, and avoid eval or interpolated `sh -c` commands.",
  tags: ["command", "injection", "input-validation"],
};

const autoApprove: RuleMetadata = {
  id: "HG006",
  title: "Overbroad auto-approval",
  defaultSeverity: "critical",
  description: "A permission or approval control is disabled or grants every operation.",
  remediation: "Turn approval checks back on and enumerate the smallest set of commands and tools the agent may use.",
  tags: ["permission", "approval", "least-privilege"],
};

const unpinnedAction: RuleMetadata = {
  id: "HG007",
  title: "Unpinned remote action",
  defaultSeverity: "medium",
  description: "A remote automation action is referenced by a mutable tag or branch.",
  remediation: "Pin the action to a reviewed 40-character commit SHA and use an update bot to propose upgrades.",
  tags: ["supply-chain", "ci", "integrity"],
};

const sensitiveWrite: RuleMetadata = {
  id: "HG008",
  title: "Sensitive path mutation",
  defaultSeverity: "high",
  description: "A hook writes to credentials, startup configuration, system settings, or another sensitive path.",
  remediation: "Write only inside a dedicated workspace directory and require approval for any host-level configuration change.",
  tags: ["filesystem", "persistence", "least-privilege"],
};

const secretOutput: RuleMetadata = {
  id: "HG009",
  title: "Secret may be written to logs",
  defaultSeverity: "high",
  description: "Tracing or output commands can expose a credential in logs or model context.",
  remediation: "Disable shell tracing around secrets and redact sensitive variables before producing output.",
  tags: ["secrets", "logging"],
};

const unverifiedArtifact: RuleMetadata = {
  id: "HG010",
  title: "Downloaded artifact executed without verification",
  defaultSeverity: "high",
  description: "A remote artifact appears to be downloaded and executed without a checksum or signature check.",
  remediation: "Pin the artifact version and verify a trusted SHA-256 digest or cryptographic signature before execution.",
  tags: ["supply-chain", "network", "integrity"],
};

const mutableImage: RuleMetadata = {
  id: "HG011",
  title: "Mutable container image",
  defaultSeverity: "medium",
  description: "A container image uses `latest`, omits a version, or is not pinned by digest.",
  remediation: "Pin the image with an immutable `@sha256:` digest and automate reviewed digest updates.",
  tags: ["supply-chain", "container", "integrity"],
};

const inheritedEnvironment: RuleMetadata = {
  id: "HG012",
  title: "Entire environment exposed",
  defaultSeverity: "high",
  description: "The hook inherits or forwards every environment variable, including unrelated credentials.",
  remediation: "Start from an empty environment and pass an explicit list of non-secret variables.",
  tags: ["secrets", "permission", "least-privilege"],
};

const broadFilesystem: RuleMetadata = {
  id: "HG013",
  title: "Unrestricted filesystem permission",
  defaultSeverity: "critical",
  description: "The agent is allowed to read or write the whole filesystem or home directory.",
  remediation: "Restrict access to the repository and a dedicated temporary directory; make all other paths read-only or denied.",
  tags: ["filesystem", "permission", "least-privilege"],
};

const insecureTls: RuleMetadata = {
  id: "HG014",
  title: "TLS verification disabled",
  defaultSeverity: "high",
  description: "The command disables certificate verification and can accept a man-in-the-middle response.",
  remediation: "Restore certificate verification and configure a trusted CA explicitly when private infrastructure requires it.",
  tags: ["network", "tls"],
};

const inlineSecret: RuleMetadata = {
  id: "HG015",
  title: "Hard-coded credential",
  defaultSeverity: "critical",
  description: "Configuration appears to contain a literal credential.",
  remediation: "Revoke the credential, remove it from history, and inject a narrowly scoped secret through the CI or runtime secret store.",
  tags: ["secrets", "credential"],
};

const rules: readonly Rule[] = [
  {
    meta: destructive,
    detect(context) {
      const match = context.line.match(/\b(?:rm\s+(?:(?:-[A-Za-z]*[rf][A-Za-z]*|--(?:recursive|force))\s+)+(?:--\s+)?["']?(?:\/|~|\$(?:HOME|\{HOME\})|\*|\.\.\/|\.(?:\/)?["']?(?:\s|$))|git\s+reset\s+--hard\b|git\s+clean\s+(?=[^\n]{0,60}(?:-[A-Za-z]*f|--force))(?=[^\n]{0,60}(?:-[A-Za-z]*d|--directories))[^\n]{0,60}|mkfs(?:\.[a-z0-9]+)?(?:\s|$)|dd\s+[^\n]{0,200}\bof=["']?\/dev\/(?:disk|rdisk|sd|nvme|vd)[^\s"']*|diskutil\s+(?:erase|partition)\b|shutdown(?:\s|$)|reboot(?:\s|$)|:\(\)\s*\{)/i);
      return match === null ? undefined : hit(destructive, context, throughLine(context, match));
    },
  },
  {
    meta: remotePipe,
    detect(context) {
      const match = context.window.match(/\b(?:curl|wget)\b[^\n]{0,500}(?:\n[^\n]{0,500}){0,2}?\|\s*(?:sudo(?:\s+-[A-Za-z]+)*\s+)?(?:(?:\/usr\/bin\/env|env)\s+)?(?:\/[A-Za-z0-9_.-]+\/)*(?:sh|bash|zsh|fish|node|python\d*|ruby|perl|pwsh|powershell|iex|Invoke-Expression)\b/i);
      return match === null ? undefined : hit(remotePipe, context, match);
    },
  },
  {
    meta: exfiltration,
    detect(context) {
      const command = continuedCommand(context);
      if (!/\b(?:curl|wget|nc|netcat|Invoke-WebRequest)\b|https?:\/\//i.test(command)) return undefined;
      if (!/(?:\$(?:\{|\()?(?:[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|CREDENTIAL|GITHUB_PAT)[A-Z0-9_]*)|(?:~|\$HOME|\$\{HOME\})?\/?(?:\.ssh|\.aws|\.gnupg|\.config\/gh|\.kube\/config|\.docker\/config\.json|\.netrc|\.npmrc)|\/etc\/(?:shadow|passwd))/i.test(command)) return undefined;
      const hosts = hostsFrom(command);
      const host = hosts.find((candidate) => !hostAllowed(candidate, context.policy));
      if (hosts.length > 0 && host === undefined) return undefined;
      const match = command.match(/\b(?:curl|wget|nc|netcat|Invoke-WebRequest)\b[^\n]*(?:\n[^\n]*){0,2}/i) ?? command.match(/https?:\/\/[^\s]+/i);
      return match === null ? undefined : hit(exfiltration, context, match, host === undefined ? undefined : `Sensitive material may be sent to ${host}.`);
    },
  },
  {
    meta: openNetwork,
    detect(context) {
      const match = context.window.match(/\b(?:network(?:Access|Permission|Policy)?|allowedHosts|allowDomains|domains)\b["']?\s*[:=]\s*(?:-\s*)?(?:["']?(?:\*|all|any)["']?|["']?true["']?|\[\s*["']?(?:\*|all|any)["']?\s*\])/i);
      return match === null ? undefined : hit(openNetwork, context, match);
    },
  },
  {
    meta: injection,
    detect(context) {
      const direct = context.line.match(/\beval\s+(?:["']?\$|`)|\b(?:sh|bash|zsh)\s+-c\s+(?:["'][^\n]*(?:\$\{|\$[A-Za-z_]|\$\()[^\n]*["']|(?:\$\{?[A-Za-z_]|\$\())/i);
      if (direct !== null) return hit(injection, context, throughLine(context, direct));
      const workflow = context.line.match(/\brun\s*:\s*.*\$\{\{\s*(?:github\.(?:event|head_ref|ref_name)|inputs\.|steps\.[^.]+\.outputs)/i);
      return workflow === null ? undefined : hit(injection, context, workflow, "Workflow-controlled data is interpolated directly into a shell step.");
    },
  },
  {
    meta: autoApprove,
    detect(context) {
      const match = context.window.match(/\b(?:dangerouslyDisableSandbox|dangerouslySkipPermissions|disablePermissions?|bypassPermissions?|skipApproval|autoApprove|auto_approve|yoloMode|permissions?)\b["']?\s*[:=]\s*(?:["']?true["']?|["']?(?:\*|all|any|everything|write-all|bypassPermissions|dontAsk)["']?)|\b(?:permissionMode|defaultMode)\b["']?\s*[:=]\s*["']?(?:bypassPermissions|dontAsk)["']?|\b(?:allowedTools|allow)\b["']?\s*[:=]\s*(?:\[[^\]]{0,300}["'](?:\*|Bash\(\*\)|all|any|everything)["']|(?:-\s*)?["'](?:\*|Bash\(\*\)|all|any|everything)["'])/i);
      return match === null ? undefined : hit(autoApprove, context, match);
    },
  },
  {
    meta: unpinnedAction,
    detect(context) {
      const match = context.line.match(/\buses\s*:\s*([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.\/-]+)?)@([^\s#"']+)/i);
      if (match === null) return undefined;
      const action = match[1] ?? "";
      const ref = match[2] ?? "";
      if (/^[a-f0-9]{40}$/i.test(ref) || context.policy.trustedActions.includes(`${action}@${ref}`) || context.policy.trustedActions.includes(action)) return undefined;
      return hit(unpinnedAction, context, match, `${action}@${ref} is mutable.`);
    },
  },
  {
    meta: sensitiveWrite,
    detect(context) {
      const match = context.line.match(/(?:>>?|\btee\b|\b(?:cp|mv|install|chmod|chown|rm|touch|mkdir|sed\s+-i)\b|\bcurl\b[^\n]{0,120}\s-o\s+|\bwget\b[^\n]{0,120}\s-O\s+)[^\n]{0,200}["']?(?:(?:~|\$HOME|\$\{HOME\})\/(?:\.ssh(?:\/|\b)|\.aws\/credentials|\.gnupg(?:\/|\b)|\.config\/(?:gh|git)\/|\.kube\/config\b|\.docker\/config\.json\b|\.netrc\b|\.npmrc\b|\.bashrc\b|\.zshrc\b)|\/etc(?:\/|\b)|\/Library\/Launch(?:Agents|Daemons))/i);
      return match === null ? undefined : hit(sensitiveWrite, context, throughLine(context, match));
    },
  },
  {
    meta: secretOutput,
    detect(context) {
      const trace = context.line.match(/(?:^|[;&|]\s*)set\s+(?:-x|-o\s+xtrace)(?:\s|$)/);
      if (trace !== null) return hit(secretOutput, context, throughLine(context, trace), "Shell tracing can copy later credentials into logs.", "medium");
      const match = context.line.match(/\b(?:echo|printf|printenv|Write-Output)\b[^\n]{0,160}\$(?:\{)?[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|CREDENTIAL)[A-Z0-9_]*(?:\})?/i);
      return match === null ? undefined : hit(secretOutput, context, throughLine(context, match));
    },
  },
  {
    meta: unverifiedArtifact,
    detect(context) {
      const download = /\b(?:curl|wget)\b/i.exec(context.window);
      if (download === null) return undefined;
      if (/\b(?:curl|wget)\b[^\n]{0,500}(?:\n[^\n]{0,500}){0,2}?\|\s*(?:sudo(?:\s+-[A-Za-z]+)*\s+)?(?:(?:\/usr\/bin\/env|env)\s+)?(?:\/[A-Za-z0-9_.-]+\/)*(?:sh|bash|zsh|fish|node|python\d*|ruby|perl|pwsh|powershell)\b/i.test(context.window)) return undefined;
      const afterDownload = context.window.slice((download.index ?? 0) + download[0].length);
      const execution = /(?:&&|;|\n)\s*(?:exec\s+|source\s+|\.\s+|(?:\.\/|\/tmp\/)[A-Za-z0-9_.-]+|(?:sh|bash|zsh|node|python\d*|ruby|perl)\s+[^\s;&|]+)/i.exec(afterDownload);
      if (execution === null) return undefined;
      const beforeExecution = afterDownload.slice(0, execution.index);
      if (/\b(?:sha256sum\s+(?:-c|--check)|shasum\s+-a\s+256\s+(?:-c|--check)|cosign\s+verify|gpg\s+--verify|openssl\s+dgst\b[^\n]*(?:-verify|-signature))\b/i.test(beforeExecution)) return undefined;
      const start = download.index ?? 0;
      const length = download[0].length + execution.index + execution[0].length;
      const match = /[\s\S]+/.exec(context.window.slice(start, start + length));
      return match === null ? undefined : hit(unverifiedArtifact, context, Object.assign(match, { index: start }));
    },
  },
  {
    meta: mutableImage,
    detect(context) {
      const match = context.line.match(/\b(?:image\s*:\s*|uses\s*:\s*docker:\/\/|docker\s+pull\s+)(["']?)([a-z0-9][a-z0-9._/:@-]*)\1/i);
      if (match === null) return undefined;
      const reference = match[2] ?? "";
      if (/@sha256:[a-f0-9]{64}$/i.test(reference)) return undefined;
      return hit(mutableImage, context, match);
    },
  },
  {
    meta: inheritedEnvironment,
    detect(context) {
      const match = context.window.match(/\b(?:inheritEnv(?:ironment)?|passEnv(?:ironment)?|forwardEnv(?:ironment)?|environment|env)\b["']?\s*[:=]\s*(?:-\s*)?(?:["']?true["']?|["']?(?:\*|all)["']?|\[\s*["']?(?:\*|all)["']?\s*\])/i);
      return match === null ? undefined : hit(inheritedEnvironment, context, match);
    },
  },
  {
    meta: broadFilesystem,
    detect(context) {
      const match = context.window.match(/\b(?:filesystem|fileSystem|allowedPaths|writePaths|readPaths|allowedDirectories|additionalDirectories|workspaceAccess)\b["']?\s*[:=]\s*(?:-\s*)?(?:["']?(?:\/|~|\*|\*\*|all|read-write)["']?|\[\s*["']?(?:\/|~|\*|\*\*)["']?\s*\])/i);
      return match === null ? undefined : hit(broadFilesystem, context, match);
    },
  },
  {
    meta: insecureTls,
    detect(context) {
      const match = context.line.match(/(?:\bcurl\b[^\n]*(?:\s-k(?:\s|$)|--insecure\b)|\bwget\b[^\n]*--no-check-certificate\b|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0|GIT_SSL_NO_VERIFY\s*=\s*["']?(?:1|true)|\bgit\s+-c\s+http\.sslVerify=false\b|\bnpm\s+config\s+set\s+strict-ssl\s+false\b)/i);
      return match === null ? undefined : hit(insecureTls, context, throughLine(context, match));
    },
  },
  {
    meta: inlineSecret,
    detect(context) {
      const match = context.line.match(/\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|token|password|passwd|secret|client[_-]?secret|private[_-]?key|credential)\b["']?\s*[:=]\s*(?:(["'])([^$<{][^"'\r\n]{11,})\1|([^"'$<{\s,#][^"'\s,#]{11,}))|\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,})\b/i);
      if (match === null) return undefined;
      const value = match[2] ?? match[3] ?? "";
      if (/^(?:example|placeholder|changeme|redacted|dummy|test|fake|sample|not-a-real|replace[_-]?me|your[_-])/i.test(value) || /^x+$/.test(value)) return undefined;
      return hit(inlineSecret, context, match);
    },
  },
];

export const RULES: readonly RuleMetadata[] = Object.freeze(rules.map((rule) => Object.freeze(rule.meta)));

export function runRules(input: ScanInput, policy: Policy): RuleHit[] {
  const originalLines = input.content.split(/\r?\n/);
  const lines = maskedContent(input).split(/\r?\n/);
  const hits: RuleHit[] = [];
  const seen = new Set<string>();
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? "";
    const window = lines.slice(index, index + 3).join("\n");
    const originalWindow = originalLines.slice(index, index + 3).join("\n");
    const context: LineContext = { input, lines, index, line, window, originalWindow, policy };
    for (const rule of rules) {
      if (policy.disabledRules.includes(rule.meta.id)) continue;
      const result = rule.detect(context);
      if (result === undefined) continue;
      const key = `${result.ruleId}:${result.line}:${result.column}`;
      if (seen.has(key)) continue;
      seen.add(key);
      hits.push(result);
    }
  }
  return hits;
}
