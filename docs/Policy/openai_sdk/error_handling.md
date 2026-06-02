---
policy_id: openai_sdk_error_handling
category: openai_sdk
topic: error_handling
rules:
  - id: OAI-008
    severity: medium
    confidence: 0.6
    scope: tool
    fix_type: code
references: [LLM05]
---

# Policy Rationale: Error Handling

**Policy ID:** `openai_sdk_error_handling`  
**File:** `openai_sdk/error_handling.yaml`  
**Rules:** OAI-008  
**Severities:** medium  
**Fix types:** code  
**References:** LLM05

> **Read [claude_sdk/error_handling.md](../claude_sdk/error_handling.md) for the full threat model.**
> This document covers OpenAI Agents SDK–specific differences only.

---

## What this policy covers

OpenAI Agents SDK `@function_tool` bodies that can `raise` but have no
`try`/`except` to shape the failure (`has_raise: true`, `has_try_except: false`).
Same predicate and threat model as the Claude error-handling policy.

---

## Why error handling is a distinct concern in agent tools

Identical to the Claude case — the model is the consumer of the failure, and an
unstructured exception gives it no retryable/permanent signal (so it loops or
gives up) and may leak internals into the context. See
[claude_sdk/error_handling.md](../claude_sdk/error_handling.md#why-error-handling-is-a-distinct-concern-in-agent-tools).

OpenAI-specific note: this SDK provides a dedicated mechanism, the
`failure_error_function` decorator kwarg, that controls exactly what the model
sees when a tool raises. This policy (a missing in-body `try/except`) is therefore
closely tied to the `decorator_config` rules: OAI-004 flags the absence of
`failure_error_function`, and OAI-015 flags the dangerous
`failure_error_function=None` (re-raise, aborting the run). A tool that relies on a
well-written `failure_error_function` may legitimately have no in-body try/except —
the most common false positive for OAI-008.

---

## Rule-by-rule defense

### OAI-008 — Tool raises exceptions without a structured error contract (Severity: medium, Confidence: 0.6, Fix type: code)

**What we detect:** a tool body with a `raise` and no `try`/`except`.

**Why it is flaggable:** the raised exception reaches the model as an opaque
string with no recovery contract, and may carry internal detail.

**Real-world consequence:** `charge_card(...)` raising `ValueError("gateway 503")`
on a transient fault gives the model no "retryable" hint; it may retry a completed
charge or abandon a recoverable one.

**Why severity is medium and not high:** reliability/minor-leak rather than a direct
breach; mishandled errors in side-effecting tools still cause real wrong actions.

**Fix type — code:** wrap the body and return a structured error.

**Confidence 0.6:** lower by design — a tool with a `failure_error_function`
(OAI-004's domain) legitimately needs no in-body try/except (false positive), and a
try/except that silently swallows errors passes the rule while being worse.

---

## What this policy does not cover

Same gaps as [claude_sdk/error_handling.md](../claude_sdk/error_handling.md#what-this-policy-does-not-cover),
plus the OpenAI-specific case: a tool handled entirely by `failure_error_function`
rather than in-body try/except (covered by OAI-004 / OAI-015 in `decorator_config`).

---

## Recommendations beyond the fix

The safe pattern — a structured `{error, retryable}` shape keyed off exception
*type*, with internals scrubbed — is in
[claude_sdk/error_handling.md](../claude_sdk/error_handling.md#recommendations-beyond-the-fix).
For the OpenAI SDK, pair it with a `failure_error_function` that returns the same
structured shape for uncaught exceptions, and never set `failure_error_function=None`
on a tool that can raise (OAI-015).
