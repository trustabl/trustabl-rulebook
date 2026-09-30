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

### MCP-013 — TypeScript MCP tool fetches a caller-controlled URL (SSRF) (Severity: high, Confidence: 0.6, Fix type: code)

**What we detect:** the same pattern in a TypeScript handler — a `fetch`/`axios`/
`got`/`undici` call whose first argument is a template string, identifier, or
concatenation rather than a string literal (captured `dynamic_url` fact).

**Why high / 0.6:** identical mechanism and calibration to MCP-008 on the
TypeScript SDK; a plain string-literal URL does not fire.

---

## Allow-list credit

MCP-008, MCP-013 used to fire on every non-literal destination, including tools that had already constrained the host, which made the rule a false-positive source for exactly the code that followed its own fix advice. The match is now `has_dynamic_url_call` **and not** a recognized host allow-list in the tool body. Severity, confidence and scope are unchanged.

**Python (MCP-008).** The rule is silenced when the function body contains a hostname membership test against a named allow-list: `.hostname not in`, `.netloc not in`, or one of `ALLOWED_HOSTS`, `ALLOWED_DOMAINS`, `allowed_hosts`, `allowed_domains`, `HOST_ALLOWLIST`, `host_allowlist` (predicate `not: has_body_text`). A bare `.hostname in` is deliberately *not* credited, because it cannot tell an allow-list from a deny-list.

**TypeScript (MCP-013).** The rule is silenced when the handler both reads a host (`.hostname` / `.host`) and tests membership (`.includes(` / `.has(`), or references a named allow-list (`allowedHosts`, `allowedDomains`, `ALLOWED_HOSTS`, `ALLOWED_DOMAINS`, `hostAllowlist`). Reading `new URL(x).hostname` with no membership test does not silence it.

The credit is textual and body-local. It does not verify that the allow-list is correct, that the check runs before the request, or that the request cannot be redirected to a host outside it; HTTPS-only enforcement and a redirect cap are recommended in each rule's fix text but are not separately detected.

---

## What this policy does not cover

Whether the dynamic URL is genuinely attacker-controlled vs a fixed-base path;
allow-list validation outside the recognized names (see Allow-list credit); DNS-rebinding and redirect-based SSRF
after an initially-safe host; and clients outside the recognized set.
- An allow-list enforced in a helper or middleware outside the tool body, an allow-list check that uses a name outside the recognized set, and a membership test that is unrelated to the URL host but happens to sit beside a `.host` read (TypeScript over-credit). Redirects and non-HTTPS schemes are not detected.
