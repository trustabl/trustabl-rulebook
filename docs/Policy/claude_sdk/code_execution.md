---
policy_id: claude_sdk_code_execution
category: claude_sdk
topic: code_execution
rules:
  - id: CSDK-107
    severity: high
    confidence: 0.85
    scope: tool
    fix_type: code
references: [LLM05, LLM06]
---

# Policy Rationale: Dynamic Code Execution

**Policy ID:** `claude_sdk_code_execution`  
**File:** `claude_sdk/code_execution.yaml`  
**Rules:** CSDK-107  
**Severities:** high  
**Fix types:** code  
**References:** LLM05, LLM06

> **Read [openai_sdk/code_execution.md](../openai_sdk/code_execution.md) for the full threat model.**
> This document covers Claude Agent SDK–specific differences only.

---

## What this policy covers

Claude Agent SDK `@tool` / `@claude_tool` bodies that invoke Python's `eval`,
`exec`, or `compile` (predicate `has_code_exec_call`, a bare-builtin AST match,
so `re.compile` and other attribute calls do not fire).

---

## Why dynamic code execution is a distinct concern in agent tools

The mechanism is identical to the OpenAI case: with any model-influenced input,
`eval`/`exec`/`compile` is arbitrary code execution inside the agent process,
with no OS sandbox between the call and the runtime's imports, file handles, and
in-memory credentials. See
[openai_sdk/code_execution.md](../openai_sdk/code_execution.md#why-dynamic-code-execution-is-a-distinct-concern-in-agent-tools).

Claude-specific note: a Claude Agent SDK tool that evaluates model-supplied code
can reach back into the host application's process — including any API keys or
session state held in memory — and, on a developer machine running with
`bypassPermissions` (see [repo.md](repo.md)), do so with no approval prompt
between the model and the `exec`.

---

## Rule-by-rule defense

### CSDK-107 — Tool body calls eval/exec/compile on dynamic input (Severity: high, Confidence: 0.85, Fix type: code)

**What we detect:**
A Claude SDK tool whose body calls the bare `eval`, `exec`, or `compile` builtin
(`has_code_exec_call`).

**Why it is flaggable:**
Dynamic evaluation in a model-callable tool is an arbitrary-code-execution
surface whenever any part of the evaluated string originates with the model.

**Real-world consequence:**
A `calculate(expr)` tool implemented as `eval(expr)` is driven into
`__import__('os').environ` to read secrets, or into reading/writing files the
process can touch.

**Why severity is high and not medium:**
No in-band sandbox stands between the call and the full runtime; a restricted
`exec` is still escapable via `__builtins__` unless explicitly stripped, so the
only reliable fix is removing dynamic evaluation.

**Fix type — code:**
Remove or replace `eval`/`exec`/`compile` — a source edit.

**Confidence 0.85:**
Same profile as OAI-013 — the bare-callee match avoids the `re.compile` false
positive, but a dynamic-eval helper in another module, or evaluation via
`types.FunctionType` / `marshal`, escapes the body-only walk.

---

## What this policy does not cover

Identical to [openai_sdk/code_execution.md](../openai_sdk/code_execution.md#what-this-policy-does-not-cover):
eval/exec reached through a helper in another module, alternative dynamic-code
primitives (`types.FunctionType`, `marshal.loads`, `pickle.loads`,
`importlib`-driven loading), and evaluations whose input is provably constant.

---

## Recommendations beyond the fix

The safe pattern — `ast.literal_eval` for arithmetic, a constrained interpreter
only where genuinely required, and a sacrificial single-use process for
intentional code-execution surfaces — is in
[openai_sdk/code_execution.md](../openai_sdk/code_execution.md#recommendations-beyond-the-fix).
For Claude SDK tools specifically, never run such a tool on a session configured
with `permission_mode="bypassPermissions"`, and keep application secrets out of
the process that hosts an evaluation tool.
