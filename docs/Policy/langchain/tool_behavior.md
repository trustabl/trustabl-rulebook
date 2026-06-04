---
policy_id: langchain_tool_behavior
category: langchain
topic: tool_behavior
rules:
  - id: LC-006
    severity: medium
    confidence: 0.8
    scope: tool
    fix_type: config
  - id: LC-014
    severity: medium
    confidence: 0.8
    scope: tool
    fix_type: config
references: [LLM05, LLM06]
---

# Policy Rationale: LangChain Tool Behavior

**Policy ID:** `langchain_tool_behavior`
**File:** `langchain/tool_behavior.yaml`
**Rules:** LC-006, LC-014
**Severities:** medium
**Fix types:** config
**References:** LLM05 (Improper Output Handling), LLM06 (Excessive Agency)

---

## What this policy covers

The LangChain-specific `return_direct` flag (`returnDirect` in TypeScript). When a
tool sets it true, LangChain returns the tool's raw output straight to the caller
and **halts the agent loop** — the model never observes the result. Discovery
captures the flag into `ToolDef.Config` (from the `@tool` decorator kwargs, the
`StructuredTool` constructor, or the TS `tool()` config object), and the rules
match it with `tool_decorator_kwarg_value`.

This is a behavioral configuration check, not a body check — hence `fix_type:
config`.

---

## Why returning directly is a reliability and safety concern

The agent loop's value is that the model *observes* each tool result and decides
what to do next — including validating it, summarizing it, retrying on error, and
running any output guardrail or formatting step. `return_direct=True` removes that
step entirely:

- **Improper output handling (LLM05):** whatever the tool returns — a raw stack
  trace, an unsanitized chunk of fetched web content, a database row containing
  secrets — is handed to the user verbatim. No model step and no post-tool
  guardrail runs to redact or reshape it. If the tool fetches external content,
  this is also a stored-prompt-injection delivery path straight to the user.
- **Broken control flow (LLM06):** any plan that expected the model to act on the
  tool result silently stops. A multi-step task that calls a "search" tool with
  `return_direct=True` ends at the search results, never reaching the synthesis the
  user asked for.

`return_direct` has legitimate uses (a terminal "hand off to human" tool), which is
why this is medium, not high — but it is frequently set without appreciating that
it disables the very loop that makes the tool safe to expose.

---

## Rule-by-rule defense

### LC-006 — Python tool returns its output directly (Severity: medium, Confidence: 0.8, Fix type: config)

**What we detect:** a Python LangChain tool whose captured config has
`return_direct` equal to `True` (predicate `tool_decorator_kwarg_value`, kwarg
`return_direct`, value `True`). Covers the `@tool(return_direct=True)` decorator and
the `StructuredTool(..., return_direct=True)` constructor.

**Why it is flaggable / consequence:** as above — the model is bypassed and raw
output reaches the user, breaking validation, guardrails, and multi-step plans.

**Severity medium:** real reliability/exposure impact, but it is sometimes
intentional, so it is a finding to review rather than a defect to remove on sight.
**Confidence 0.8:** the deliberate "terminal tool" use is a genuine false-positive
class.

### LC-014 — TypeScript tool returns its output directly (Severity: medium, Confidence: 0.8, Fix type: config)

**What we detect:** a TS LangChain tool whose config has `returnDirect: true`
(captured into `ToolDef.Config` by discovery).

**Why it is flaggable / consequence:** identical to LC-006 in LangChain.js.

**Severity medium / Confidence 0.8:** same profile.

---

## What this policy does not cover

`return_direct` set dynamically (a computed expression rather than a literal),
`response_format="content_and_artifact"` (a related but distinct output-shape
flag), and the *content* of what a direct-returning tool emits — the rule flags the
control-flow change, not the specific data exposed.

---

## Recommendations beyond the fix

Leave `return_direct` / `returnDirect` at its default (false) unless you
specifically intend to short-circuit the agent. If you do, treat the tool's output
as untrusted user-facing data: sanitize and shape it inside the tool, since no
model step or guardrail runs after it. For a "final answer" pattern, prefer a
structured response the model emits after observing the tool, not a raw passthrough.
