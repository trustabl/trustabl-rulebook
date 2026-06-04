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
references: [LLM06, LLM02]
---

# Policy Rationale: LangChain SSRF

**Policy ID:** `langchain_ssrf`
**File:** `langchain/ssrf.yaml`
**Rules:** LC-005, LC-013
**Severities:** high
**Fix types:** code
**References:** LLM06 (Excessive Agency), LLM02 (Sensitive Information Disclosure)

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
