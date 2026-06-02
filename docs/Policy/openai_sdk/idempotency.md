---
policy_id: openai_sdk_idempotency
category: openai_sdk
topic: idempotency
rules:
  - id: OAI-009
    severity: medium
    confidence: 0.55
    scope: tool
    fix_type: code
references: [LLM06]
---

# Policy Rationale: Idempotency

**Policy ID:** `openai_sdk_idempotency`  
**File:** `openai_sdk/idempotency.yaml`  
**Rules:** OAI-009  
**Severities:** medium  
**Fix types:** code  
**References:** LLM06

> **Read [claude_sdk/idempotency.md](../claude_sdk/idempotency.md) for the full threat model.**
> This document covers OpenAI Agents SDK–specific differences only.

---

## What this policy covers

OpenAI Agents SDK `@function_tool` functions whose name signals a mutating action
(`create`, `send`, `charge`, `delete`, …, via `name_has_prefix`) but whose
parameters carry no idempotency key (`param_name_matches`). Same predicates and
threat model as the Claude idempotency policy.

---

## Why idempotency is a distinct concern in agent tools

Identical to the Claude case — agents retry, and a mutating tool with no dedupe key
cannot tell a retry from a new request, so a retried side effect double-fires (the
timeout double-spend). See
[claude_sdk/idempotency.md](../claude_sdk/idempotency.md#why-idempotency-is-a-distinct-concern-in-agent-tools).

OpenAI-specific note: retries here come from two places — the model re-calling the
tool, and an opaque tool error (no `failure_error_function`, OAI-004) prompting the
model to try again. Tightening error contracts reduces spurious retries, but the
idempotency key is the actual safeguard.

---

## Rule-by-rule defense

### OAI-009 — Mutating tool has no idempotency key (Severity: medium, Confidence: 0.55, Fix type: code)

**What we detect:** a tool whose name begins with a mutating verb and whose
parameters contain no idempotency-key-shaped name.

**Why it is flaggable:** without a dedupe key, an agent retry double-fires the side
effect.

**Real-world consequence:** `charge_card(token, cents)` retried after a lost
response bills the customer twice.

**Why severity is medium and not high:** real but conditional on a retry occurring
and the backend not deduping by other means.

**Fix type — code:** add an idempotency-key parameter and thread it to the backend.

**Confidence 0.55:** the pack's lowest by design — backend-enforced idempotency,
non-mutating verbs, and keys named outside the heuristic are all common false
positives. A review prompt, not a verdict.

---

## What this policy does not cover

Same gaps as [claude_sdk/idempotency.md](../claude_sdk/idempotency.md#what-this-policy-does-not-cover):
backend-enforced idempotency, mutating names outside the verb set, whether a present
key is actually honored, and deliberate double-invocation.

---

## Recommendations beyond the fix

The safe pattern — require the key, document reuse-on-retry, honor it end-to-end —
is in [claude_sdk/idempotency.md](../claude_sdk/idempotency.md#recommendations-beyond-the-fix).
For the OpenAI SDK, also give the tool a structured `failure_error_function`
(OAI-004) so an ambiguous failure does not provoke a blind retry in the first place.
