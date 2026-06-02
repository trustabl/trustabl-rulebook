---
policy_id: claude_sdk_network
category: claude_sdk
topic: network
rules:
  - id: CSDK-003
    severity: high
    confidence: 0.85
    scope: tool
    fix_type: code
references: [LLM10]
---

# Policy Rationale: Network Call Hygiene

**Policy ID:** `claude_sdk_network`  
**File:** `claude_sdk/network.yaml`  
**Rules:** CSDK-003  
**Severities:** high  
**Fix types:** code  
**References:** LLM10

> **Read [openai_sdk/network.md](../openai_sdk/network.md) for the full threat model.**
> This document covers Claude Agent SDK–specific differences only.

---

## What this policy covers

Claude Agent SDK `@tool` / `@claude_tool` bodies (and MCP tool registrations)
that make an outbound HTTP call without a `timeout=` keyword argument. Detection
is the `call_without_kwarg` predicate over the `requests.*` / `httpx.*` /
`urllib.request.urlopen` callee families — the same mechanism described in the
OpenAI network doc, including local client-alias resolution
(`s = requests.Session(); s.get(...)`).

---

## Why network hygiene is a distinct concern in agent tools

The mechanism is identical to the OpenAI case — a timeout-less call hangs on a
stalled socket, and because the model drives the call sequence, one hung request
freezes the whole conversation turn rather than a single cancellable request.
See [openai_sdk/network.md](../openai_sdk/network.md#why-network-hygiene-is-a-distinct-concern-in-agent-tools).

Claude-specific note: the Claude Agent SDK does not impose a tool-level wall
clock either, so a hung `requests.get` blocks the agent loop until the OS TCP
timeout (minutes). The same rule applies to MCP tools, where the blocked call
also stalls whatever external orchestrator invoked the MCP server.

---

## Rule-by-rule defense

### CSDK-003 — Network call has no timeout (Severity: high, Confidence: 0.85, Fix type: code)

**What we detect:**
A Claude SDK or MCP tool whose body calls a `requests` / `httpx` method,
`urllib.request.urlopen`, or a resolved session alias of these, with no
`timeout=` kwarg (the kwarg absent, or present as `None`, both count).

**Why it is flaggable:**
These clients default to no timeout; without one the call blocks until the kernel
gives up, pinning the agent loop.

**Real-world consequence:**
A `fetch_page(url)` Claude tool called on a slow host hangs the turn — the user
sees nothing, and the model's retry on the eventual error compounds the stall.

**Why severity is high and not medium:**
The failure denies the agent loop itself, with no in-band mitigation short of an
explicit `timeout=`. Same reasoning as OAI-005/011.

**Fix type — code:**
Add `timeout=` to the call — a source edit; no hook or sandbox injects it.

**Confidence 0.85:**
Same profile as the OpenAI network rules — a client whose timeout is configured
on a `Session`/`Client` object rather than the call site can be a false positive,
and a request behind a cross-module helper a false negative.

---

## What this policy does not cover

Identical to [openai_sdk/network.md](../openai_sdk/network.md#what-this-policy-does-not-cover):
non-listed clients (`aiohttp`, raw `socket`, `pycurl`), unreasonable-but-present
timeout values, transitive calls through another module, and retry-without-backoff
storms (idempotency territory, CSDK-006).

---

## Recommendations beyond the fix

The safe pattern — an explicit `timeout=`, a capped response read, and a
structured error the model can branch on — is in
[openai_sdk/network.md](../openai_sdk/network.md#recommendations-beyond-the-fix).
For Claude SDK tools, return a structured error dict on timeout so the model can
react rather than seeing an opaque traceback, and prefer a single shared client
with a default timeout if many tools fetch the same service.
