---
policy_id: mcp_ssrf
category: mcp
topic: ssrf
rules:
  - id: MCP-008
    severity: high
    confidence: 0.6
    scope: tool
    fix_type: code
  - id: MCP-013
    severity: high
    confidence: 0.6
    scope: tool
    fix_type: code
references: [LLM06, LLM02]
---

# Policy Rationale: MCP Server-Side Request Forgery

**Policy ID:** `mcp_ssrf`  
**File:** `mcp/ssrf.yaml`  
**Rules:** MCP-008, MCP-013  
**References:** LLM06 (Excessive Agency), LLM02 (Sensitive Information Disclosure)

> Shares the SSRF threat model with [openai_sdk/ssrf.md](../openai_sdk/ssrf.md).
> MCP-specific angle only.

---

## What this policy covers

An MCP tool handler issuing an HTTP request to a non-literal URL —
`has_dynamic_url_call` over the recognized clients (Python `requests`/`httpx`/
`urllib`; TypeScript `fetch`/`axios`/`got`/`undici` via the captured
`dynamic_url` handler fact). MCP-008 is the Python rule, MCP-013 the TypeScript
rule.

## Why SSRF is a server-boundary problem for MCP

An MCP tool argument arrives from a connecting client and is chosen by a model
from conversation context. If that value flows into the request URL, an attacker
who can shape the context steers the request at any host the **server** can reach
but the public internet cannot — cloud metadata endpoints (169.254.169.254) that
vend credentials, loopback admin APIs, internal services. The MCP server becomes
a proxy for requests the attacker could not otherwise make (LLM06), and the
response plus any request body leaks back across the trust boundary (LLM02).

---

## Rule-by-rule defense

### MCP-008 — Tool fetches a caller-controlled URL (SSRF) (Severity: high, Confidence: 0.6, Fix type: code)

**What we detect:** a Python handler whose outbound request URL is built from a
parameter or an interpolated string rather than a fixed literal.

**Why high / 0.6:** the consequence (credential theft via metadata, internal
pivot) is severe, so severity is high; confidence is 0.6 because "non-literal
URL" includes benign cases where the dynamic part is a fixed-base path segment,
and the rule cannot prove the value is attacker-reachable.

**Real-world consequence:** a stale, forgotten-but-still-live internal system — one that was supposed to be decommissioned but never was, with credentials for it sitting in an accessible file — is a plausible SSRF target: nobody is watching it, so a steered request against it goes unnoticed until data is already gone. The consequence isn't always data theft, either. In one publicly-relevant case, an attacker used an internal foothold to lock a company and its customers out of a cloud-hosted system entirely — no data was actually accessed (so it wasn't a reportable breach), but the business couldn't operate until a ransom was paid. An SSRF-reachable internal endpoint is a plausible entry point for that class of availability attack, not only for credential exfiltration.

### MCP-013 — TypeScript MCP tool fetches a caller-controlled URL (SSRF) (Severity: high, Confidence: 0.6, Fix type: code)

**What we detect:** the same pattern in a TypeScript handler — a `fetch`/`axios`/
`got`/`undici` call whose first argument is a template string, identifier, or
concatenation rather than a string literal (captured `dynamic_url` fact).

**Why high / 0.6:** identical mechanism and calibration to MCP-008 on the
TypeScript SDK; a plain string-literal URL does not fire.

**Real-world consequence:** same consequence class as MCP-008 — stale internal systems and availability/ransom attacks are language-agnostic outcomes of a successful SSRF, not specific to the Python SDK.

---

## What this policy does not cover

Whether the dynamic URL is genuinely attacker-controlled vs a fixed-base path;
allow-list validation the rule cannot see; DNS-rebinding and redirect-based SSRF
after an initially-safe host; and clients outside the recognized set.
