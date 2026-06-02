---
policy_id: claude_sdk_shell_safety
category: claude_sdk
topic: shell_safety
rules:
  - id: CSDK-108
    severity: high
    confidence: 0.7
    scope: tool
    fix_type: code
references: [LLM06, LLM05]
---

# Policy Rationale: Shell Safety

**Policy ID:** `claude_sdk_shell_safety`  
**File:** `claude_sdk/shell_safety.yaml`  
**Rules:** CSDK-108  
**Severities:** high  
**Fix types:** code  
**References:** LLM06, LLM05

> **Read [openai_sdk/shell_safety.md](../openai_sdk/shell_safety.md) for the full threat model.**
> This document covers Claude Agent SDK–specific differences only.

---

## What this policy covers

Claude Agent SDK `@tool` / `@claude_tool` bodies that spawn an OS process
(predicate `has_shell_call`: a resolved callee of `os.system`, `os.popen`, any
`subprocess.*`, or any `os.spawn*` — an AST match, not a substring scan).

---

## Why shell execution is a distinct concern in agent tools

The mechanism is identical to the OpenAI case — the model selects the command,
and the subprocess inherits the runtime's full filesystem, environment, and
credentials with no framework sandbox. See
[openai_sdk/shell_safety.md](../openai_sdk/shell_safety.md#why-shell-execution-is-a-distinct-concern-in-agent-tools).

Claude-specific note: Claude Code's built-in `Bash` tool is the sanctioned,
permission-gated way to run commands; a hand-rolled `@tool` that shells out
**bypasses that gate**, putting process spawn on the model's surface without the
approval prompt. On a session running `bypassPermissions` (see [repo.md](repo.md))
there is then nothing between an injected instruction and arbitrary command
execution.

---

## Rule-by-rule defense

### CSDK-108 — Tool body spawns a subprocess (Severity: high, Confidence: 0.7, Fix type: code)

**What we detect:**
A Claude SDK tool whose body calls `os.system`, `os.popen`, any `subprocess.*`
function, or any `os.spawn*` function (`has_shell_call`).

**Why it is flaggable:**
Process spawn from a model-callable tool puts the OS shell on the model's
surface; the presence of the spawn is the signal.

**Real-world consequence:**
A `run_command(cmd)` Claude tool forwarding `cmd` into `subprocess.run(cmd,
shell=True)` is one injected instruction away from reading `~/.ssh/id_rsa` or
exfiltrating environment secrets.

**Why severity is high and not medium:**
The fix usually means removing process spawn or rearchitecting behind a typed
API; partial mitigations narrow specific injection classes but not the
excessive-agency core.

**Fix type — code:**
Replace the spawn with a library call or front it with an allow-list — a source
edit.

**Confidence 0.7:**
Slightly lower than the OpenAI equivalent's 0.9 to reflect that some Claude tool
authors legitimately wrap a single fixed command; the `subprocess.*` prefix also
over-fires on the non-spawning `subprocess.list2cmdline` helper, and a spawn
hidden behind a cross-module helper escapes the body-only walk.

---

## What this policy does not cover

Identical to [openai_sdk/shell_safety.md](../openai_sdk/shell_safety.md#what-this-policy-does-not-cover):
`asyncio.create_subprocess_*`, `pty.spawn` / `pexpect`, `multiprocessing.Process`,
the `os.exec*` family, a spawn wrapped behind a helper in another module, and the
question of whether a given literal command is safe. The HTTP-exfiltration path is
covered by SSRF ([ssrf.md](ssrf.md), CSDK-008).

---

## Recommendations beyond the fix

The safe pattern — typed library API, argv list with `shell=False`, `timeout=`,
sandboxing, and dropped env vars — is in
[openai_sdk/shell_safety.md](../openai_sdk/shell_safety.md#recommendations-beyond-the-fix).
For Claude specifically: prefer Claude Code's permission-gated built-in `Bash`
tool over a hand-rolled subprocess tool, and never expose a shell-spawning tool on
a `bypassPermissions` session.
