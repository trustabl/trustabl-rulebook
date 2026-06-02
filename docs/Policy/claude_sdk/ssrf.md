---
policy_id: claude_sdk_ssrf
category: claude_sdk
topic: ssrf
rules:
  - id: CSDK-008
    severity: high
    confidence: 0.6
    scope: tool
    fix_type: code
references: [LLM06, LLM02]
---

# Policy Rationale: Server-Side Request Forgery

**Policy ID:** `claude_sdk_ssrf`  
**File:** `claude_sdk/ssrf.yaml`  
**Rules:** CSDK-008  
**Severities:** high  
**Fix types:** code  
**References:** LLM06, LLM02

> **Read [openai_sdk/ssrf.md](../openai_sdk/ssrf.md) for the full threat model.**
> This document covers Claude Agent SDK–specific differences only.

---

## What this policy covers

Claude Agent SDK `@tool` / `@claude_tool` bodies — and MCP tool registrations
(`@server.tool` / `@mcp.tool`), since `applies_to` includes `mcp_tool` — that
issue an HTTP request to a non-literal destination URL. Detection is the same
`has_dynamic_url_call` AST predicate described in the OpenAI doc: it fires when
the URL argument of a `requests` / `httpx` call (including resolved session
aliases) is a parameter, an interpolated f-string, or a built-up expression
rather than a fixed literal.

---

## Why SSRF is a distinct concern in agent tools

The mechanism is identical to the OpenAI case (the model chooses the URL the
tool fetches; the payoff is reaching internal/metadata endpoints the agent host
can address). See [openai_sdk/ssrf.md](../openai_sdk/ssrf.md#why-ssrf-is-a-distinct-concern-in-agent-tools).

Two Claude-specific notes. First, the rule also applies to **MCP tools**: an MCP
server exposes its tools to *any* orchestrator that connects, and the tool
author often has no visibility into which agent — or which user — is driving the
calls, so a model-controlled URL in an MCP tool is reachable across trust
boundaries the tool author never sees. Second, the Claude Agent SDK provides no
network egress control of its own; a tool that fetches a dynamic URL has the
full network reach of the process hosting the SDK, with nothing between the model
and the request.

---

## Rule-by-rule defense

### CSDK-008 — Tool fetches a caller-controlled URL (SSRF) (Severity: high, Confidence: 0.6, Fix type: code)

**What we detect:**
A `@tool` / `@claude_tool` / `claude_agent_sdk` or MCP-registered function whose
body makes an HTTP call with a non-literal URL argument (predicate
`has_dynamic_url_call`, an AST walk — comments and docstrings do not fire).

**Why it is flaggable:**
A non-literal URL means the destination host is effectively model-chosen. For an
MCP tool the caller is doubly untrusted — an external orchestrator with
fully model-controlled inputs.

**Real-world consequence:**
- A Claude `@tool def read_page(url: str)` is prompt-injected into fetching the
  cloud metadata endpoint and returns short-lived credentials into the
  conversation.
- An MCP `@server.tool def proxy(target: str)` exposed to a desktop client is
  driven at `http://localhost:<port>` admin services on the user's machine.

**Why severity is high and not medium:**
Same reasoning as OAI-016 — single-call credential/internal-data exposure, fully
fixable by a host allow-list, impact conditional on the host's network position.

**Fix type — code:**
The destination constraint lives in the tool's own source (allow-list, fixed
base URL, post-resolution IP checks).

**Confidence 0.6:**
Same false-positive/false-negative profile as OAI-016 — a guard in another
module is invisible to the body-only walk, and a URL assembled indirectly can
evade the first-argument check. Strong lead, not a certainty.

---

## What this policy does not cover

Identical to [openai_sdk/ssrf.md](../openai_sdk/ssrf.md#what-this-policy-does-not-cover):
out-of-module URL validation, `urllib`/`aiohttp`/raw-socket targets, literal
base + path-traversal/userinfo redirect tricks, DNS rebinding and redirect-based
SSRF, and the safety of the fetched content itself. For MCP tools specifically,
the rule also cannot see *which* orchestrator is connected, so it cannot
distinguish a locked-down deployment from an exposed one.

---

## Recommendations beyond the fix

The safe pattern is identical to the OpenAI doc — an explicit **host** allow-list,
post-resolution rejection of private/loopback/link-local IPs, and disabled
redirects. See [openai_sdk/ssrf.md](../openai_sdk/ssrf.md#recommendations-beyond-the-fix)
for the full runnable example. Claude-specific additions:

1. For MCP tools, document the intended deployment trust boundary in the tool
   description and treat the URL parameter as fully hostile regardless.
2. Prefer fixing the base URL in code and accepting only a path/query from the
   model, since MCP tool callers are the least trusted input source.
