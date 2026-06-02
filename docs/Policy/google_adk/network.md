---
policy_id: google_adk_network
category: google_adk
topic: network
rules:
  - id: ADK-003
    severity: high
    confidence: 0.85
    scope: tool
    fix_type: code
references: [LLM10]
---

# Policy Rationale: Network Call Hygiene

**Policy ID:** `google_adk_network`  
**File:** `google_adk/network.yaml`  
**Rules:** ADK-003  
**Severities:** high  
**Fix types:** code  
**References:** LLM10

> **Read [openai_sdk/network.md](../openai_sdk/network.md) for the full threat model.**
> This document covers Google ADK–specific differences only.

---

## What this policy covers

Google ADK `FunctionTool`-wrapped functions that make an outbound HTTP call
(`requests.*` / `httpx.*`) without a `timeout=` keyword argument
(`call_without_kwarg`, alias-aware). Same predicate and threat model as the
OpenAI/Claude network policies.

---

## Why network hygiene is a distinct concern in agent tools

Identical to the OpenAI case — a timeout-less call hangs on a stalled socket, and
because the model drives the call sequence, one hung request freezes the whole
turn. See [openai_sdk/network.md](../openai_sdk/network.md#why-network-hygiene-is-a-distinct-concern-in-agent-tools).

ADK-specific note: ADK has no tool-level wall clock, so a hung request blocks the
agent loop until the OS TCP timeout (minutes). On managed runtimes (Cloud Run,
Vertex AI) a stuck request also holds a request slot, so under load timeout-less
tools degrade availability for the whole service.

---

## Rule-by-rule defense

### ADK-003 — Network call has no timeout (Severity: high, Confidence: 0.85, Fix type: code)

**What we detect:** a `FunctionTool`-wrapped body calling `requests`/`httpx`
methods (or a resolved session alias) with no `timeout=` kwarg.

**Why it is flaggable:** these clients default to no timeout; the call blocks until
the kernel gives up, pinning the agent loop.

**Real-world consequence:** a `get_weather(city)` tool hits a slow endpoint and the
whole ADK turn hangs; the model's retry compounds it.

**Why severity is high and not medium:** it denies the agent loop itself, with no
mitigation short of an explicit `timeout=`.

**Fix type — code:** add `timeout=` to the call.

**Confidence 0.85:** same profile as the other network rules — a client whose
timeout is configured on a session object, or a request behind a cross-module
helper, can be a false positive/negative.

---

## What this policy does not cover

Same gaps as [openai_sdk/network.md](../openai_sdk/network.md#what-this-policy-does-not-cover):
non-listed clients, unreasonable-but-present timeout values, transitive calls
through another module, and retry-without-backoff storms (idempotency, ADK-006).

---

## Recommendations beyond the fix

The safe pattern — explicit `timeout=`, capped response read, structured error —
is in [openai_sdk/network.md](../openai_sdk/network.md#recommendations-beyond-the-fix).
For ADK, return a structured error dict the Gemini model can branch on, and set a
defensive timeout tight enough to free the managed-runtime request slot quickly.
