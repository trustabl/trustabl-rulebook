---
policy_id: langchain_shell_safety
category: langchain
topic: shell_safety
rules:
  - id: LC-003
    severity: high
    confidence: 0.85
    scope: tool
    fix_type: code
  - id: LC-011
    severity: high
    confidence: 0.85
    scope: tool
    fix_type: code
references: [LLM06, LLM05]
---

# Policy Rationale: LangChain Shell Safety

**Policy ID:** `langchain_shell_safety`
**File:** `langchain/shell_safety.yaml`
**Rules:** LC-003, LC-011
**Severities:** high
**Fix types:** code
**References:** LLM06 (Excessive Agency), LLM05 (Improper Output Handling)

> **Read [openai_sdk/shell_safety.md](../openai_sdk/shell_safety.md) for the full
> threat model.** This document covers the LangChain-specific differences only.

---

## What this policy covers

LangChain tools whose body spawns an OS process. Python (LC-003) uses the same
`has_shell_call` AST predicate as the OpenAI/ADK packs — a resolved callee of
`os.system`, `os.popen`, any `subprocess.*`, or any `os.spawn*`. TypeScript
(LC-011) reads the discovery-computed `shells_out` fact, set when a tool handler
calls a `child_process` primitive (`exec`, `execSync`, `spawn`, `fork`, …).

For the Python factory forms (`StructuredTool.from_function(fn)`), discovery points
the tool at the wrapped function body, so the predicate scans the real
implementation, not the registration call site.

---

## Why shell execution is a distinct concern in LangChain agents

The mechanism is identical to the OpenAI case (the model selects the command; the
subprocess inherits the runtime's filesystem, environment, and credentials) — see
[openai_sdk/shell_safety.md](../openai_sdk/shell_safety.md#why-shell-execution-is-a-distinct-concern-in-agent-tools).

The LangChain-specific sharpening: LangChain ships a first-class `ShellTool`
(recognized at agent scope by LC-101), so shelling out is a *normalized* pattern
in this ecosystem rather than an exception. A hand-rolled `subprocess.run(cmd,
shell=True)` inside a `@tool` carries the identical risk as `ShellTool` but with
none of its (minimal) guardrails, and it hides inside an ordinary-looking tool. In
a ReAct loop the command string is chosen by the model from tool output and prior
context, so a single injected instruction reaches the shell.

---

## Rule-by-rule defense

### LC-003 — Python tool body spawns a subprocess (Severity: high, Confidence: 0.85, Fix type: code)

**What we detect:** a Python LangChain tool whose body invokes `os.system`,
`os.popen`, a `subprocess.*` function, or an `os.spawn*` function (predicate
`has_shell_call`, an AST callee walk, not a substring scan).

**Why it is flaggable:** process spawn from a model-callable tool puts the OS shell
on the model's tool surface. The presence of the spawn is the signal; every
safeguard is bolted onto an inherently broad primitive.

**Real-world consequence:** a `run(cmd)` tool forwarding a model string into
`subprocess.run(cmd, shell=True)` is one prompt injection from arbitrary command
execution with the agent's privileges.

**Severity high:** the fix usually means removing the spawn or rearchitecting
behind a typed API. Not raised above high because the exposure depends on what the
caller does with the spawn. **Confidence 0.85:** the `subprocess.*` prefix
over-fires on the rare non-spawning helper (`subprocess.list2cmdline`), and
async/`pty` spawn primitives escape the body walk.

### LC-011 — TypeScript tool body spawns a subprocess (Severity: high, Confidence: 0.85, Fix type: code)

**What we detect:** a TS LangChain tool whose handler calls a `child_process`
primitive (the `shells_out` fact set by `tsHandlerFacts`).

**Why it is flaggable / consequence:** identical to LC-003 in the Node runtime — a
model-chosen string reaching `exec`/`execSync` is a direct path from prompt
injection to RCE.

**Severity high / Confidence 0.85:** same profile; the fact is set on the bare and
`child_process.`-qualified callee forms, and a spawn hidden behind a helper in
another module escapes it.

---

## What this policy does not cover

The same gaps as [openai_sdk/shell_safety.md](../openai_sdk/shell_safety.md#what-this-policy-does-not-cover):
`asyncio.create_subprocess_*`, `pty`/`pexpect`, `multiprocessing`, the `os.exec*`
family, and spawns wrapped behind a cross-module helper. Whether a given literal
command is safe is out of scope. The `ShellTool` built-in is flagged at agent
scope by LC-101, not here.

---

## Recommendations beyond the fix

The safe pattern — typed library API, argv list with `shell=False` (or
`execFile`/`spawn` with an argument array in TS), `timeout=`, sandboxing, dropped
env vars — is in
[openai_sdk/shell_safety.md](../openai_sdk/shell_safety.md#recommendations-beyond-the-fix).
Keep shell logic out of any agent-callable tool; if a command must run, gate it
behind a human-in-the-loop approval (a LangGraph `interrupt_before` breakpoint).
