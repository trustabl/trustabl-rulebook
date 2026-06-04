---
policy_id: langchain_code_execution
category: langchain
topic: code_execution
rules:
  - id: LC-004
    severity: high
    confidence: 0.85
    scope: tool
    fix_type: code
  - id: LC-012
    severity: high
    confidence: 0.85
    scope: tool
    fix_type: code
references: [LLM05, LLM06]
---

# Policy Rationale: LangChain Dynamic Code Execution

**Policy ID:** `langchain_code_execution`
**File:** `langchain/code_execution.yaml`
**Rules:** LC-004, LC-012
**Severities:** high
**Fix types:** code
**References:** LLM05 (Improper Output Handling), LLM06 (Excessive Agency)

> **Read [openai_sdk/code_execution.md](../openai_sdk/code_execution.md) for the
> full threat model.** This document covers the LangChain-specific differences only.

---

## What this policy covers

LangChain tools whose body evaluates code at runtime. Python (LC-004) fires on a
bare `eval` / `exec` / `compile` callee (predicate `has_code_exec_call`, an AST
walk). TypeScript (LC-012) reads the `code_exec` discovery fact, set when a handler
calls `eval` or constructs `new Function(...)`.

---

## Why dynamic evaluation is a distinct concern in LangChain agents

The mechanism is identical to the OpenAI case — a model-influenced string reaching
an interpreter is arbitrary code execution; see
[openai_sdk/code_execution.md](../openai_sdk/code_execution.md). The
LangChain-specific note is that this ecosystem *ships* code execution as a feature:
`PythonREPLTool` / `PythonAstREPLTool` (flagged at agent scope by LC-101) and the
pandas/CSV/SQL "dataframe" agents are built on a REPL. Hand-rolling `eval()` inside
a `@tool` reproduces that capability with none of the (already thin) sandboxing the
REPL tools attempt, and hides it inside an ordinary tool body. The result reaches
the model and the user unsanitized (LLM05), and the model can drive it (LLM06).

---

## Rule-by-rule defense

### LC-004 — Python tool body evaluates dynamic code (Severity: high, Confidence: 0.85, Fix type: code)

**What we detect:** a Python LangChain tool whose body calls `eval`, `exec`, or
`compile` as a bare builtin (so `re.compile` and other attribute calls are not
flagged).

**Why it is flaggable / consequence:** a tool that evaluates its string input can
be steered by prompt injection to run attacker-chosen Python in the agent process —
read secrets, pivot to the network, or rewrite state.

**Severity high:** the fix is to remove the evaluation or sandbox it; partial input
filtering does not contain `eval`. **Confidence 0.85:** the bare-callee match
avoids the obvious false positives, but a tool that only ever evaluates a trusted
constant is over-flagged.

### LC-012 — TypeScript tool evaluates dynamic code (Severity: high, Confidence: 0.85, Fix type: code)

**What we detect:** a TS LangChain tool whose handler calls `eval()` or
`new Function(...)` (the `code_exec` fact).

**Why it is flaggable / consequence:** identical in the Node runtime — both
evaluate a string as code, so a model-influenced argument is RCE.

**Severity high / Confidence 0.85:** same profile as LC-004.

---

## What this policy does not cover

Indirect evaluation (`importlib`, `pickle.loads`, `vm.runInContext`, a templating
engine with code execution), evaluation behind a cross-module helper, and the
`PythonREPLTool` built-in itself (agent scope, LC-101). Whether a given evaluated
string is attacker-reachable is not proven — the presence of the primitive is the
signal.

---

## Recommendations beyond the fix

Parse structured input with a real parser (`ast.literal_eval` / `JSON.parse` / a
typed schema) instead of evaluating it. If code execution is genuinely the product,
run it in a locked-down sandbox (no filesystem, no network, no credentials, hard
timeout) and gate it behind a human approval rather than letting the model invoke
it unattended.
