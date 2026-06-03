---
policy_id: claude_sdk_code_execution
category: claude_sdk
topic: code_execution
rules:
  - id: CSDK-011
    severity: high
    confidence: 0.9
    scope: tool
    fix_type: code
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
**Rules:** CSDK-011, CSDK-107  
**Severities:** high, high  
**Fix types:** code, code  
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

### CSDK-011 — TypeScript Claude SDK tool evaluates dynamic code (Severity: high, Confidence: 0.9, Fix type: code)

**What we detect:**
A TypeScript Claude Agent SDK `tool(...)` whose handler body calls the bare
`eval()` builtin or constructs `new Function(...)` (predicate
`has_code_exec_call`, backed by the structural `code_exec` fact in
`ts_handler_facts.go`). The fact fires on two AST shapes only: a `call_expression`
whose callee text is exactly `eval`, and a `new_expression` whose constructor
identifier text is exactly `Function`. The exact-callee match means a method named
`retrieval(...)` or a member call like `obj.eval(...)` does not fire — only the
bare global `eval` and `new Function`.

**Why it is flaggable:**
`eval` and `new Function` compile a string into executable JavaScript in the
agent's own process. When any part of that string originates with the model — a
tool argument, or state the model wrote — the tool is an arbitrary-code-execution
surface with no process boundary and no SDK sandbox between the call and the
runtime's imports, file handles, and in-memory credentials. This is the TypeScript
analogue of the Python `eval`/`exec`/`compile` mechanism documented for
[CSDK-107](#csdk-107--tool-body-calls-evalexeccompile-on-dynamic-input-severity-high-confidence-085-fix-type-code).

**Real-world consequence:**
A `calculate(expr)` tool implemented as `return eval(expr)` is driven by an
injected instruction into `process.env` to read secrets, or into
`require('child_process').execSync(...)` to run commands — the full Node runtime is
reachable from a single evaluated string.

**Why severity is high and not medium:**
There is no in-band sandbox between the evaluated string and the Node runtime;
unlike Python there is not even a partial `__builtins__`-stripping mitigation to
reach for, since `new Function` always closes over the global scope. The only
reliable fix is removing dynamic evaluation, so the gap is not partially
mitigable — high, matching the Python sibling.

**Fix type — code:**
Removing `eval` / `new Function` and dispatching on a fixed operation map is an
edit to the tool's own source.

**Confidence 0.9:**
Marginally higher than the Python sibling's 0.85. The structural `code_exec` fact
keys on the exact callee text `eval` and the exact constructor `Function`, so the
two dominant false positives are eliminated by construction: a same-named method
(`x.eval(...)`) and an unrelated identifier do not match. The residual gap is the
false negative — dynamic execution reached through an indirect alias
(`const e = eval; e(s)`), a `require('vm')` context, or a code-exec helper in
another module escapes the handler-body-only walk. There is no `re.compile`-style
false positive here (no TS builtin collides with the matched names), which is why
confidence sits above the Python rule.

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

For the Python rule (CSDK-107), identical to
[openai_sdk/code_execution.md](../openai_sdk/code_execution.md#what-this-policy-does-not-cover):
eval/exec reached through a helper in another module, alternative dynamic-code
primitives (`types.FunctionType`, `marshal.loads`, `pickle.loads`,
`importlib`-driven loading), and evaluations whose input is provably constant.

For the TypeScript rule (CSDK-011), the structural fact matches only the bare
`eval` callee and `new Function` constructor in the handler body, so these escape:
- `eval` reached through an alias (`const e = eval; e(s)`) or a property access
  (`window.eval`, `globalThis.eval`).
- The `vm` module (`vm.runInNewContext`, `vm.runInThisContext`,
  `new vm.Script(...)`), `require`/dynamic `import()` of attacker-named modules,
  and `setTimeout("...string...", 0)` string-form evaluation — none are in the
  matched set.
- A code-exec call in a helper in another module, since the walk sees only the
  tool's own handler.
- Evaluations whose argument is provably a constant literal (the fact does not
  reason about whether the evaluated string is model-controlled — it flags the
  presence of the primitive).

---

## Recommendations beyond the fix

The safe pattern — `ast.literal_eval` for arithmetic, a constrained interpreter
only where genuinely required, and a sacrificial single-use process for
intentional code-execution surfaces — is in
[openai_sdk/code_execution.md](../openai_sdk/code_execution.md#recommendations-beyond-the-fix).
For Claude SDK tools specifically, never run such a tool on a session configured
with `permission_mode="bypassPermissions"`, and keep application secrets out of
the process that hosts an evaluation tool.
