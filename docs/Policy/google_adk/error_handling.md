---
policy_id: google_adk_error_handling
category: google_adk
topic: error_handling
rules:
  - id: ADK-005
    severity: medium
    confidence: 0.6
    scope: tool
    fix_type: code
references: [LLM05]
---

# Policy Rationale: Error Handling

**Policy ID:** `google_adk_error_handling`  
**File:** `google_adk/error_handling.yaml`  
**Rules:** ADK-005  
**Severities:** medium  
**Fix types:** code  
**References:** LLM05

> **Read [claude_sdk/error_handling.md](../claude_sdk/error_handling.md) for the full threat model.**
> This document covers Google ADK–specific differences only.

---

## What this policy covers

Google ADK `FunctionTool`-wrapped functions that can `raise` but have no
`try`/`except` to shape the failure (`has_raise: true`, `has_try_except: false`).
Same predicate and threat model as the Claude error-handling policy.

---

## Why error handling is a distinct concern in agent tools

Identical to the Claude case — the model is the consumer of the failure, and an
unstructured exception gives it no retryable/permanent signal and may leak
internals. See
[claude_sdk/error_handling.md](../claude_sdk/error_handling.md#why-error-handling-is-a-distinct-concern-in-agent-tools).

ADK-specific note: the idiomatic ADK contract is for a tool to **return** a
structured dict (often `{"status": "error", "error_message": ...}`) rather than
raise, so the Gemini model gets a typed result. An uncaught raise breaks that
contract and surfaces a raw exception instead.

---

## Rule-by-rule defense

### ADK-005 — Tool raises exceptions without a structured error contract (Severity: medium, Confidence: 0.6, Fix type: code)

**What we detect:** a wrapped-function body with a `raise` and no `try`/`except`.

**Why it is flaggable:** the exception reaches the model as an opaque string with no
recovery contract, breaking ADK's return-a-dict convention.

**Real-world consequence:** a transient fault raised as `ValueError` gives the model
no "retryable" hint; it retries a completed action or abandons a recoverable one.

**Why severity is medium and not high:** reliability/minor-leak rather than a direct
breach; mishandled errors in side-effecting tools still cause real wrong actions.

**Fix type — code:** wrap the body and return a structured error dict.

**Confidence 0.6:** lower by design — a tool whose raise is handled by an outer ADK
wrapper, or one that returns errors elsewhere, can be a false positive; a try/except
that swallows errors passes the rule while being worse.

---

## What this policy does not cover

Same gaps as [claude_sdk/error_handling.md](../claude_sdk/error_handling.md#what-this-policy-does-not-cover):
externally-handled raises, swallow-and-continue try/except blocks, the content of a
structured error that is present, and exceptions raised in a cross-module helper.

---

## Recommendations beyond the fix

The safe pattern — a structured `{status, error_message, retryable}` shape keyed off
exception *type*, internals scrubbed — adapts the example in
[claude_sdk/error_handling.md](../claude_sdk/error_handling.md#recommendations-beyond-the-fix)
to ADK's return-a-dict convention. Return the dict; do not let the exception escape
the tool.
