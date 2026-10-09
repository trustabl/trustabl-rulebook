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

> **Read [claude_sdk/ssrf.md](../claude_sdk/ssrf.md) for the full threat model.**
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
[claude_sdk/ssrf.md](../claude_sdk/ssrf.md). The LangChain-specific note: this
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

## Allow-list credit

LC-005, LC-013 used to fire on every non-literal destination, including tools that had already constrained the host, which made the rule a false-positive source for exactly the code that followed its own fix advice. The match is now `has_dynamic_url_call` **and not** a recognized host allow-list in the tool body. Severity, confidence and scope are unchanged.

**Python (LC-005).** The rule is silenced when the function body contains a hostname membership test against a named allow-list: `.hostname not in`, `.netloc not in`, or one of `ALLOWED_HOSTS`, `ALLOWED_DOMAINS`, `allowed_hosts`, `allowed_domains`, `HOST_ALLOWLIST`, `host_allowlist` (predicate `not: has_body_text`). A bare `.hostname in` is deliberately *not* credited, because it cannot tell an allow-list from a deny-list.

**TypeScript (LC-013).** The rule is silenced when the handler both reads a host (`.hostname` / `.host`) and tests membership (`.includes(` / `.has(`), or references a named allow-list (`allowedHosts`, `allowedDomains`, `ALLOWED_HOSTS`, `ALLOWED_DOMAINS`, `hostAllowlist`). Reading `new URL(x).hostname` with no membership test does not silence it.

The credit is textual and body-local. It does not verify that the allow-list is correct, that the check runs before the request, or that the request cannot be redirected to a host outside it; HTTPS-only enforcement and a redirect cap are recommended in each rule's fix text but are not separately detected.

---

## What this policy does not cover

Whether an allow-list is actually enforced downstream, redirects into private
ranges, DNS-rebinding, and URLs assembled across function boundaries. A literal
base URL with only a model-supplied path is treated as safe by the dynamic-URL
check even though path traversal on the target may still matter.
- An allow-list enforced in a helper or middleware outside the tool body, an allow-list check that uses a name outside the recognized set, and a membership test that is unrelated to the URL host but happens to sit beside a `.host` read (TypeScript over-credit). Redirects and non-HTTPS schemes are not detected.

---

## Recommendations beyond the fix

Validate the URL against a host allow-list, reject private and link-local ranges
(and redirects into them), and never pass a raw model-supplied URL to the HTTP
client. If the tool talks to one service, hard-code the base URL and accept only a
path/query from the model. The full safe pattern is in
[claude_sdk/ssrf.md](../claude_sdk/ssrf.md#recommendations-beyond-the-fix).
