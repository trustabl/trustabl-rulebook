---
policy_id: claude_sdk_shell_safety
category: claude_sdk
topic: shell_safety
rules:
  - id: CSDK-010
    severity: high
    confidence: 0.7
    scope: tool
    fix_type: code
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
**Rules:** CSDK-010, CSDK-108  
**Severities:** high, high  
**Fix types:** code, code  
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

### CSDK-010 — TypeScript Claude SDK tool shells out to the OS (Severity: high, Confidence: 0.7, Fix type: code)

**What we detect:**
A TypeScript Claude SDK `tool(...)` whose handler body invokes a child-process
API — `exec`, `execSync`, `execFile`, `execFileSync`, `spawn`, `spawnSync`, or
`fork`, whether called bare (from a destructured `const { exec } = ...`) or via a
`child_process.*` namespace — detected by the structured `has_shell_call`
predicate. During discovery `tsHandlerFacts` walks the handler AST and stamps a
`shells_out` fact when it sees one of those callees; `has_shell_call` reads that
fact for TypeScript (and walks the AST directly for Python). This is a callee
match, **not** a substring scan, so the string appearing in a comment, an
unrelated identifier, or a string literal does not fire it.

**Why it is flaggable:**
A child-process API in a model-callable tool puts OS process spawn on the model's
surface. Because the agent chooses the arguments it passes to the tool, a
prompt-injected conversation can steer those values into a command. The mechanism
is the same excessive-agency core documented for the Python sibling
[CSDK-108](#csdk-108--tool-body-spawns-a-subprocess-severity-high-confidence-07-fix-type-code);
the only delta is the API surface (`child_process.exec`/`execSync`/`spawn` vs
Python `subprocess.*` / `os.system`).

**Real-world consequence:**
A `runCommand(cmd)` tool forwarding `cmd` into `execSync(cmd)` (which runs through
`/bin/sh`) is one injected instruction away from `cat ~/.ssh/id_rsa` or
exfiltrating `process.env`.

**Why severity is high and not medium:**
The fix usually means removing process spawn or rearchitecting behind a typed API;
partial mitigations narrow specific injection classes but not the excessive-agency
core. Matches the Python sibling's high.

**Fix type — code:**
Replacing the spawn with a library call, or fronting it with an argv array and an
allow-list, is an edit to the tool's own source.

**Confidence 0.7:**
Matches the Python sibling's 0.7 and now shares its mechanism (a structured
callee match, not a substring scan). False positives: a tool that legitimately
wraps a single fixed command still fires — the rule detects that the tool *shells
out*, not that it does so unsafely. False negatives: a spawn reached via a
renamed destructured alias (`const { exec: run } = ...; run(...)`) whose callee
text matches none of the recognized names, or one hidden in a helper in another
module, is not seen. The 0.7 reflects this "shells out at all" framing rather than
any substring imprecision — the earlier substring detection's comment/string-literal
false positives no longer apply.

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

For the Python rule (CSDK-108), identical to
[openai_sdk/shell_safety.md](../openai_sdk/shell_safety.md#what-this-policy-does-not-cover):
`asyncio.create_subprocess_*`, `pty.spawn` / `pexpect`, `multiprocessing.Process`,
the `os.exec*` family, a spawn wrapped behind a helper in another module, and the
question of whether a given literal command is safe.

For the TypeScript rule (CSDK-010), the recognized callees are `exec`,
`execSync`, `execFile`, `execFileSync`, `spawn`, `spawnSync`, `fork` (bare or
`child_process.*`-qualified), so these escape:
- A child-process call reached through a renamed alias whose callee text matches
  none of the recognized names (`const { exec: run } = ...; run(...)`), or one in
  a helper in another module.
- Other process-spawning paths whose callee is not in the set — e.g. `Bun.spawn`,
  `Deno.Command`, `node:worker_threads`, or a native addon.
- Whether a given literal command is actually safe (the rule's signal is that the
  tool shells out at all, not that it does so unsafely).

The HTTP-exfiltration path is covered by SSRF ([ssrf.md](ssrf.md), CSDK-009 /
CSDK-013).

---

## Recommendations beyond the fix

The safe pattern — typed library API, argv list with `shell=False`, `timeout=`,
sandboxing, and dropped env vars — is in
[openai_sdk/shell_safety.md](../openai_sdk/shell_safety.md#recommendations-beyond-the-fix).
For Claude specifically: prefer Claude Code's permission-gated built-in `Bash`
tool over a hand-rolled subprocess tool, and never expose a shell-spawning tool on
a `bypassPermissions` session.
