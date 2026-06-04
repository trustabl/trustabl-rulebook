---
policy_id: mcp_shell_safety
category: mcp
topic: shell_safety
rules:
  - id: MCP-010
    severity: high
    confidence: 0.7
    scope: tool
    fix_type: code
  - id: MCP-012
    severity: high
    confidence: 0.7
    scope: tool
    fix_type: code
references: [LLM06, LLM05]
---

# Policy Rationale: MCP Shell Invocation Safety

**Policy ID:** `mcp_shell_safety`  
**File:** `mcp/shell_safety.yaml`  
**Rules:** MCP-010, MCP-012  
**References:** LLM06 (Excessive Agency), LLM05 (Improper Output Handling)

> Shares the process-spawn threat model with
> [openai_sdk/shell_safety.md](../openai_sdk/shell_safety.md). MCP-specific angle
> only.

---

## What this policy covers

An MCP tool handler that spawns an OS process — Python `subprocess.*` /
`os.system` / `os.popen` / `os.spawn*` (MCP-010) or a TypeScript child-process
API `exec`/`execSync`/`execFile`/`spawn`/`fork`, bare or `child_process.*`
(MCP-012). Both read the structured `has_shell_call` predicate (Python walks the
AST; TypeScript reads the `shells_out` fact stamped by `tsHandlerFacts`), so a
match in a comment or string literal does not fire.

## Why process spawn in an MCP handler is excessive agency

Process spawn from a model-callable MCP tool puts the server host's shell on the
model's surface with no runtime sandbox. Because a connecting model chooses the
arguments passed to the tool, a prompt-injected conversation can steer those
values into a command (LLM06); the subprocess inherits the server host's
filesystem, environment, and network credentials, and its output returns across
the trust boundary (LLM05).

---

## Rule-by-rule defense

### MCP-010 — Tool body spawns a subprocess (Severity: high, Confidence: 0.7, Fix type: code)

**What we detect:** a Python handler calling `subprocess.*`, `os.system`,
`os.popen`, or `os.spawn*`.

**Why high / 0.7:** the fix usually means removing process spawn or rearchitecting
behind a typed API; partial mitigations narrow injection classes but not the
excessive-agency core. Confidence 0.7 because some handlers legitimately wrap a
single fixed command, and the `subprocess.` prefix also catches the non-spawning
`subprocess.list2cmdline` helper.

### MCP-012 — TypeScript MCP tool spawns a subprocess (Severity: high, Confidence: 0.7, Fix type: code)

**What we detect:** a TypeScript handler invoking a `child_process` API (bare from
a destructured `const { execSync } = ...` or via `child_process.*`).

**Why high / 0.7:** identical mechanism on the TypeScript SDK. The residual gaps
are a spawn reached through a renamed alias whose callee text matches no
recognized name, a helper in another module, or non-`child_process` spawners
(`Bun.spawn`, `Deno.Command`).

---

## What this policy does not cover

Whether a given literal command is actually safe; spawns hidden behind a
cross-module helper or a renamed alias; async spawners
(`asyncio.create_subprocess_*`) and non-`child_process` TypeScript spawners; and
the HTTP-exfiltration path, which SSRF ([ssrf.md](ssrf.md)) covers.
