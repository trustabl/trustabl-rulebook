---
policy_id: langchain_ssrf
category: langchain
topic: ssrf
rules:
  - id: LC-005
    severity: high
    confidence: 0.8
    scope: tool
    fix_type: code
  - id: LC-013
    severity: high
    confidence: 0.8
    scope: tool
    fix_type: code
  - id: LC-026
    severity: medium
    confidence: 0.6
    scope: tool
    fix_type: code
  - id: LC-027
    severity: medium
    confidence: 0.6
    scope: tool
    fix_type: code
references: [LLM06, LLM02, LLM01]
---

# Policy Rationale: LangChain SSRF

**Policy ID:** `langchain_ssrf`
**File:** `langchain/ssrf.yaml`
**Rules:** LC-005, LC-013, LC-026, LC-027
**Severities:** high, medium, medium
**Fix types:** code, code, code
**References:** LLM06 (Excessive Agency), LLM02 (Sensitive Information Disclosure), LLM01

> **Read [openai_sdk/ssrf.md](../openai_sdk/ssrf.md) for the full threat model.**
> This document covers the LangChain-specific differences only.

---

## What this policy covers

LangChain tools that issue an outbound HTTP request to a caller-controlled
(non-literal) URL. Python (LC-005) uses `has_dynamic_url_call` — an HTTP call
(`requests`/`httpx`/`urllib`/`aiohttp`, alias-resolved) whose first argument is not
a plain string literal. TypeScript (LC-013) reads the `dynamic_url` fact, set when a
`fetch`/`axios`/`got` call takes a non-literal URL.

---

## Why a model-controlled URL is server-side request forgery

The mechanism and the metadata-endpoint / internal-service impact are covered in
[openai_sdk/ssrf.md](../openai_sdk/ssrf.md). The LangChain-specific note: this
ecosystem ships a `RequestsToolkit` and a `Requests*` tool family whose docstrings
explicitly require `allow_dangerous_requests=True` precisely because they hand the
model an arbitrary-URL fetch. A hand-rolled `requests.get(url)` inside a `@tool`
reproduces that exposure without the explicit opt-in, so it reads as an ordinary
tool while granting the same SSRF primitive. The model — or a prompt injection in
content it already fetched — chooses the host (LLM06), reaching internal services
and credential endpoints an external caller could not (LLM02).

---

## Rule-by-rule defense

### LC-005 — Python tool fetches a caller-controlled URL (Severity: high, Confidence: 0.8, Fix type: code)

**What we detect:** a Python LangChain tool that makes an HTTP call whose URL
argument is a parameter, an f-string with substitution, or another non-literal
(predicate `has_dynamic_url_call`).

**Why it is flaggable / consequence:** the destination is model-controlled, so the
tool can be driven to `http://169.254.169.254/...` or a localhost admin port the
agent host can see. Classic SSRF handed to the model.

**Severity high:** the fix is an allow-list / SSRF guard, a real code change. **Confidence
0.8:** an internal-only deployment with no reachable sensitive endpoints lowers the
real-world impact, so the confidence is a notch below the shell/code rules.

### LC-013 — TypeScript tool fetches a caller-controlled URL (Severity: high, Confidence: 0.8, Fix type: code)

**What we detect:** a TS LangChain tool calling `fetch`/`axios`/`got` with a
non-literal URL (the `dynamic_url` fact).

**Why it is flaggable / consequence:** identical in the Node runtime.

**Severity high / Confidence 0.8:** same profile as LC-005.

### LC-026 — LangChain tool fetches an allow-listed host without pinning https:// (Severity: medium, Confidence: 0.6, Fix type: code)

**What we detect:** a Python tool whose body checks the destination host against a named allow-list (the same `has_body_text` credit that silences LC-005) and makes a recognized HTTP call (`requests`/`httpx`/`urllib`/aliased clients) with a dynamic URL that neither starts with a literal `https://` prefix nor is guarded by a scheme check (`.scheme ==`/`!=`/`in`/`not in`, `startswith("https://")`). Backed by `has_unpinned_scheme_url_call`, which treats an f-string, `+` concatenation, `%`-format, or `.format()` call whose leftmost literal starts with `https://` as pinned.

**Why it is flaggable:** the allow-list (LC-005's credit) constrains *where* the request goes, not *how*. An `http://` URL for an allowed
host passes the host check, so request headers (API keys, bearer tokens) and bodies travel in cleartext, and a network-path attacker can read
them or rewrite the response. The response re-enters the model's context as trusted tool output, which makes tampering a prompt-injection channel.
A redirect from the allowed host to `http://` has the same effect.

**Real-world consequence:** credential and data disclosure to anyone on the network path (shared Wi-Fi, compromised proxy, hostile egress hop)
and integrity loss of the content the model reasons over.

**Why medium / 0.6:** medium rather than LC-005's high because the host is already bounded, so the residual risk needs a network-path attacker
rather than just a prompt injection. Confidence is 0.6 because the scheme may be enforced where this rule cannot see it: a helper defined in
another function or module, a base URL configured on a client object, or a prefix built on an earlier line and passed by identifier.

**Staging:** the rule requires the allow-list credit to be present, so LC-005 and LC-026 never fire on the same tool: SSRF first, then HTTPS once a host
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

### LC-027 — TypeScript LangChain tool fetches an allow-listed host without pinning https:// (Severity: medium, Confidence: 0.6, Fix type: code)

**What we detect:** a TypeScript tool whose body checks `.hostname`/`.host` against an allow-list (the positive form of the credit that silences LC-013) and calls `fetch`/`axios`/`got`/`undici` with a dynamic URL that neither starts with a literal `https://` prefix nor is guarded by a `.protocol` comparison or `startsWith("https:")`. Backed by the `url_scheme_unpinned` handler fact computed beside `dynamic_url`; a template string or `+` concatenation whose leftmost fragment is a literal `https://` is treated as pinned.

**Why it is flaggable:** the allow-list (LC-013's credit) constrains *where* the request goes, not *how*. An `http://` URL for an allowed
host passes the host check, so request headers (API keys, bearer tokens) and bodies travel in cleartext, and a network-path attacker can read
them or rewrite the response. The response re-enters the model's context as trusted tool output, which makes tampering a prompt-injection channel.
A redirect from the allowed host to `http://` has the same effect.

**Real-world consequence:** credential and data disclosure to anyone on the network path (shared Wi-Fi, compromised proxy, hostile egress hop)
and integrity loss of the content the model reasons over.

**Why medium / 0.6:** medium rather than LC-013's high because the host is already bounded, so the residual risk needs a network-path attacker
rather than just a prompt injection. Confidence is 0.6 because the scheme may be enforced where this rule cannot see it: a helper defined in
another function or module, a base URL configured on a client object, or a prefix built on an earlier line and passed by identifier.

**Staging:** the rule requires the allow-list credit to be present, so LC-013 and LC-027 never fire on the same tool: SSRF first, then HTTPS once a host
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

Whether an allow-list is actually enforced downstream, redirects into private
ranges, DNS-rebinding, and URLs assembled across function boundaries. A literal
base URL with only a model-supplied path is treated as safe by the dynamic-URL
check even though path traversal on the target may still matter.

---

## Recommendations beyond the fix

Validate the URL against a host allow-list, reject private and link-local ranges
(and redirects into them), and never pass a raw model-supplied URL to the HTTP
client. If the tool talks to one service, hard-code the base URL and accept only a
path/query from the model. The full safe pattern is in
[openai_sdk/ssrf.md](../openai_sdk/ssrf.md#recommendations-beyond-the-fix).
