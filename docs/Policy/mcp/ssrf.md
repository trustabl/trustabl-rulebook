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
  - id: MCP-031
    severity: medium
    confidence: 0.6
    scope: tool
    fix_type: code
  - id: MCP-032
    severity: medium
    confidence: 0.6
    scope: tool
    fix_type: code
references: [LLM06, LLM02, LLM01]
---

# Policy Rationale: MCP Server-Side Request Forgery

**Policy ID:** `mcp_ssrf`  
**File:** `mcp/ssrf.yaml`  
**Rules:** MCP-008, MCP-013, MCP-031, MCP-032  
**References:** LLM06 (Excessive Agency), LLM02 (Sensitive Information Disclosure), LLM01

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

### MCP-031 — MCP tool fetches an allow-listed host without pinning https:// (Severity: medium, Confidence: 0.6, Fix type: code)

**What we detect:** a Python tool whose body checks the destination host against a named allow-list (the same `has_body_text` credit that silences MCP-008) and makes a recognized HTTP call (`requests`/`httpx`/`urllib`/aliased clients) with a dynamic URL that neither starts with a literal `https://` prefix nor is guarded by a scheme check (`.scheme ==`/`!=`/`in`/`not in`, `startswith("https://")`). Backed by `has_unpinned_scheme_url_call`, which treats an f-string, `+` concatenation, `%`-format, or `.format()` call whose leftmost literal starts with `https://` as pinned.

**Why it is flaggable:** the allow-list (MCP-008's credit) constrains *where* the request goes, not *how*. An `http://` URL for an allowed
host passes the host check, so request headers (API keys, bearer tokens) and bodies travel in cleartext, and a network-path attacker can read
them or rewrite the response. The response re-enters the model's context as trusted tool output, which makes tampering a prompt-injection channel.
A redirect from the allowed host to `http://` has the same effect.

**Real-world consequence:** credential and data disclosure to anyone on the network path (shared Wi-Fi, compromised proxy, hostile egress hop)
and integrity loss of the content the model reasons over.

**Why medium / 0.6:** medium rather than MCP-008's high because the host is already bounded, so the residual risk needs a network-path attacker
rather than just a prompt injection. Confidence is 0.6 because the scheme may be enforced where this rule cannot see it: a helper defined in
another function or module, a base URL configured on a client object, or a prefix built on an earlier line and passed by identifier.

**Staging:** the rule requires the allow-list credit to be present, so MCP-008 and MCP-031 never fire on the same tool: SSRF first, then HTTPS once a host
allow-list exists.

**What this does not cover:** a fully literal `http://` URL (not dynamic, so outside the SSRF family); scheme validation in another function
or file; HTTPS downgrade via a redirect chain the rule cannot trace; and HSTS or transport policy configured outside the tool body.

**Safe-code recommendation:**

```python
ALLOWED_HOSTS = {"api.example.com"}

def fetch(path: str) -> str:
    url = f"https://api.example.com/{quote(path)}"   # scheme is a literal
    if urlparse(url).hostname not in ALLOWED_HOSTS:
        raise ValueError("host not allowed")
    return requests.get(url, timeout=10, allow_redirects=False).text
```

### MCP-032 — TypeScript MCP tool fetches an allow-listed host without pinning https:// (Severity: medium, Confidence: 0.6, Fix type: code)

**What we detect:** a TypeScript tool whose body checks `.hostname`/`.host` against an allow-list (the positive form of the credit that silences MCP-013) and calls `fetch`/`axios`/`got`/`undici` with a dynamic URL that neither starts with a literal `https://` prefix nor is guarded by a `.protocol` comparison or `startsWith("https:")`. Backed by the `url_scheme_unpinned` handler fact computed beside `dynamic_url`; a template string or `+` concatenation whose leftmost fragment is a literal `https://` is treated as pinned.

**Why it is flaggable:** the allow-list (MCP-013's credit) constrains *where* the request goes, not *how*. An `http://` URL for an allowed
host passes the host check, so request headers (API keys, bearer tokens) and bodies travel in cleartext, and a network-path attacker can read
them or rewrite the response. The response re-enters the model's context as trusted tool output, which makes tampering a prompt-injection channel.
A redirect from the allowed host to `http://` has the same effect.

**Real-world consequence:** credential and data disclosure to anyone on the network path (shared Wi-Fi, compromised proxy, hostile egress hop)
and integrity loss of the content the model reasons over.

**Why medium / 0.6:** medium rather than MCP-013's high because the host is already bounded, so the residual risk needs a network-path attacker
rather than just a prompt injection. Confidence is 0.6 because the scheme may be enforced where this rule cannot see it: a helper defined in
another function or module, a base URL configured on a client object, or a prefix built on an earlier line and passed by identifier.

**Staging:** the rule requires the allow-list credit to be present, so MCP-013 and MCP-032 never fire on the same tool: SSRF first, then HTTPS once a host
allow-list exists.

**What this does not cover:** a fully literal `http://` URL (not dynamic, so outside the SSRF family); scheme validation in another function
or file; HTTPS downgrade via a redirect chain the rule cannot trace; and HSTS or transport policy configured outside the tool body.

**Safe-code recommendation:**

```ts
const ALLOWED = new Set(["api.example.com"]);

const url = new URL(`https://api.example.com/${encodeURIComponent(path)}`); // scheme is a literal
if (!ALLOWED.has(url.hostname)) throw new Error("host not allowed");
const res = await fetch(url, { redirect: "manual", signal: AbortSignal.timeout(10_000) });
```

---

## What this policy does not cover

Whether the dynamic URL is genuinely attacker-controlled vs a fixed-base path;
allow-list validation the rule cannot see; DNS-rebinding and redirect-based SSRF
after an initially-safe host; and clients outside the recognized set.
