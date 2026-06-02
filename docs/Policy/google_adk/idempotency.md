---
policy_id: google_adk_idempotency
category: google_adk
topic: idempotency
rules:
  - id: ADK-006
    severity: medium
    confidence: 0.55
    scope: tool
    fix_type: code
references: [LLM06]
---

# Policy Rationale: Idempotency

**Policy ID:** `google_adk_idempotency`  
**File:** `google_adk/idempotency.yaml`  
**Rules:** ADK-006  
**Severities:** medium  
**Fix types:** code  
**References:** LLM06

> **Read [claude_sdk/idempotency.md](../claude_sdk/idempotency.md) for the full threat model.**
> This document covers Google ADK–specific differences only.

---

## What this policy covers

Google ADK `FunctionTool`-wrapped functions whose name signals a mutating action
(`create`, `send`, `charge`, …) but whose parameters carry no idempotency key.
Same predicates and threat model as the Claude idempotency policy.

---

## Why idempotency is a distinct concern in agent tools

Identical to the Claude case — agents retry, and a mutating tool with no dedupe key
cannot tell a retry from a new request, so a retried side effect double-fires. See
[claude_sdk/idempotency.md](../claude_sdk/idempotency.md#why-idempotency-is-a-distinct-concern-in-agent-tools).

ADK-specific note: a `LoopAgent` without `max_iterations` (ADK-108) multiplies this
risk — an unbounded loop re-invoking a non-idempotent mutating tool fires the side
effect once per iteration. The two rules compound.

---

## Rule-by-rule defense

### ADK-006 — Mutating tool has no idempotency key (Severity: medium, Confidence: 0.55, Fix type: code)

**What we detect:** a wrapped function whose name begins with a mutating verb and
whose parameters contain no idempotency-key-shaped name.

**Why it is flaggable:** without a dedupe key, an agent retry (or a loop iteration)
double-fires the side effect.

**Real-world consequence:** `charge_card(token, cents)` retried after a lost response
bills the customer twice.

**Why severity is medium and not high:** real but conditional on a retry occurring
and the backend not deduping by other means.

**Fix type — code:** add an idempotency-key parameter and thread it to the backend.

**Confidence 0.55:** the pack's lowest by design — backend-enforced idempotency,
non-mutating verbs, and keys named outside the heuristic are common false positives.

---

## What this policy does not cover

Same gaps as [claude_sdk/idempotency.md](../claude_sdk/idempotency.md#what-this-policy-does-not-cover):
backend-enforced idempotency, mutating names outside the verb set, whether a present
key is honored, and deliberate double-invocation.

---

## Recommendations beyond the fix

The safe pattern — require the key, document reuse-on-retry, honor it end-to-end —
is in [claude_sdk/idempotency.md](../claude_sdk/idempotency.md#recommendations-beyond-the-fix).
For ADK, also bound any `LoopAgent` that calls a mutating tool with `max_iterations`
(ADK-108) so a missed escalation cannot re-fire the side effect indefinitely.
