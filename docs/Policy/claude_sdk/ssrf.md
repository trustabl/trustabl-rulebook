---
policy_id: claude_sdk_ssrf
category: claude_sdk
topic: ssrf
rules:
  - id: CSDK-009
    severity: high
    confidence: 0.6
    scope: tool
    fix_type: code
  - id: CSDK-013
    severity: high
    confidence: 0.6
    scope: tool
    fix_type: code
  - id: CSDK-024
    severity: medium
    confidence: 0.6
    scope: tool
    fix_type: code
  - id: CSDK-025
    severity: medium
    confidence: 0.6
    scope: tool
    fix_type: code
references: [LLM06, LLM02, LLM01]
---

# Policy Rationale: Server-Side Request Forgery

**Policy ID:** `claude_sdk_ssrf`  
**File:** `claude_sdk/ssrf.yaml`  
**Rules:** CSDK-009, CSDK-013, CSDK-024, CSDK-025  
**Severities:** high, high, medium, medium  
**Fix types:** code, code, code, code  
**References:** LLM06, LLM02, LLM01

> This is the canonical SSRF rationale for the rulebook. The OpenAI (OAI-018) and
> Google ADK (ADK-012) SSRF rules cross-reference this document for the shared
> threat model and cover only their SDK-specific differences.

---

## What this policy covers

Claude Agent SDK `@tool` / `@claude_tool` bodies — and MCP tool registrations,
since `applies_to` includes `mcp_tool` — that issue an HTTP request whose
destination URL is not a fixed literal. The detection is the structured
`has_dynamic_url_call` predicate: it walks the function's AST, identifies HTTP
call sites (the `requests` / `httpx` families and local client aliases such as
`s = requests.Session(); s.get(...)`), and fires when the URL argument is
anything other than a plain literal — a bare parameter (`requests.get(url)`), an
f-string with interpolation (`httpx.get(f"https://{host}/x")`), or a
concatenation. A request to a hard-coded literal URL does not fire.

---

## Why SSRF is a distinct concern in agent tools

In a conventional app the set of URLs a server fetches is fixed by the developer;
SSRF arises only where user input reaches a request unchecked. In an agent tool
the model *is* the caller — it chooses every argument value it passes to the
tool. A tool whose URL comes from a parameter is, by construction, a tool the
model can point anywhere. There is no separate "trusted developer input" channel;
the SDK forwards the model's chosen arguments verbatim.

The damage is not the fetch itself but *where the agent host sits on the
network*. Agent runtimes typically run inside a cloud VPC with reachability the
public internet does not have. The canonical target is the instance metadata
service — `169.254.169.254` on AWS/Azure/GCP — which vends short-lived
credentials for the attached role or service account to any process that can make
a local HTTP request. A single model-driven
`requests.get("http://169.254.169.254/latest/meta-data/iam/security-credentials/...")`
turns prompt injection into cloud credential theft. Beyond metadata, the same
primitive reaches loopback admin endpoints, internal-only microservices, and
link-local addresses — none of which expect to be addressed by an untrusted
party. The request body (auth headers, payloads) also leaks to whatever host the
URL resolves to.

This maps to OWASP LLM Top 10:2025 **LLM06 (Excessive Agency)** — the tool grants
the model a network reach far broader than its task requires — and **LLM02
(Sensitive Information Disclosure)**, because the most common payoff is credential
or internal-data exfiltration. Allow-listing the *path* while leaving the *host*
model-controlled is the trap: the host is the security boundary, not the path.

---

## Rule-by-rule defense

### CSDK-009 — Tool fetches a caller-controlled URL (SSRF) (Severity: high, Confidence: 0.6, Fix type: code)

**What we detect:**
A `@tool` / `@claude_tool` / `claude_agent_sdk` or MCP-registered function whose
body makes an HTTP call (`requests.*`, `httpx.*`, or a resolved session-alias
call) where the URL argument is not a string literal — a parameter, an
interpolated f-string, or a built-up expression (predicate
`has_dynamic_url_call`, an AST walk; comments and docstrings do not fire).

**Why it is flaggable:**
A non-literal URL in a model-callable tool means the destination host is, in
practice, chosen by the model. The presence of the dynamic URL is the signal that
the tool can be steered at hosts the author never intended.

**Real-world consequence:**
- A `read_page(url: str)` web-reader tool, when prompt-injected, is asked to fetch
  `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>`; the
  returned credentials land in the model context and from there into logs or the
  next turn.
- An MCP `proxy(target: str)` tool exposed to a desktop client is pointed at
  `http://localhost:<port>` admin services on the user's machine.

**Why severity is high and not medium:**
The exploit needs no second vulnerability — a single tool call against a reachable
metadata or internal endpoint yields credentials or internal data. It is not
critical because impact is conditional on the host's network position, and a
correct host allow-list fully neutralizes it.

**Fix type — code:**
Constraining the destination (allow-list, fixed base URL, post-resolution IP
checks) is an edit to the tool's own source. An agent-level egress firewall is
complementary but is not what the rule asks for.

**Confidence 0.6:**
Many tools legitimately fetch a parameter-supplied URL and *do* validate it — but
the validation often lives in a helper in another module that the body-only walk
cannot see, so a correctly-guarded tool can still fire. The predicate also cannot
tell a genuinely user-facing "fetch this public page" tool from an internal one.
False negatives: a URL built in a helper, or assembled via `urljoin` from a
model-controlled base, can evade the first-argument check. A strong lead to
investigate, not a near-certain defect.

### CSDK-013 — TypeScript Claude SDK tool fetches a caller-controlled URL (SSRF) (Severity: high, Confidence: 0.6, Fix type: code)

**What we detect:**
A TypeScript Claude SDK `tool(...)` whose handler issues an HTTP call to a URL
that is not a plain string literal (predicate `has_dynamic_url_call`, backed by
the structural `dynamic_url` fact in `ts_handler_facts.go`). The fact recognizes a
fixed set of HTTP call callees — `fetch`, `axios` and its method forms
(`axios.get`/`.post`/`.put`/`.delete`/`.patch`/`.request`), `got`/`got.get`/
`got.post`, and `undici.fetch`/`undici.request` — and inspects the **first
positional argument**. It fires when that argument is anything other than a plain
string literal: an identifier (`fetch(url)`), a member expression
(`fetch(opts.url)`), a string concatenation, a call expression, or a template
string that contains a `${...}` substitution. A plain `"https://..."` literal, or
a backtick template with no substitution, does not fire.

**Why it is flaggable:**
A non-literal URL argument means the destination host is, in practice, chosen by
the model. The threat model is identical to the Python sibling
[CSDK-009](#csdk-009--tool-fetches-a-caller-controlled-url-ssrf-severity-high-confidence-06-fix-type-code):
the agent host typically sits inside a VPC with reach to the instance metadata
service (`169.254.169.254`), loopback admin endpoints, and internal microservices
that the public internet cannot address. The only delta is the client library
(`fetch`/`axios`/`got`/`undici` vs Python `requests`/`httpx`).

**Real-world consequence:**
A `readPage(url: string)` web-reader tool, when prompt-injected, is asked to fetch
`http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` via
`fetch(url)`; the returned credentials land in the model context and from there
into logs or the next turn.

**Why severity is high and not medium:**
The exploit needs no second vulnerability — one tool call against a reachable
metadata or internal endpoint yields credentials or internal data. It is not
critical because impact is conditional on the host's network position, and a
correct host allow-list fully neutralizes it. Matches the Python sibling.

**Fix type — code:**
Constraining the destination (host allow-list, post-resolution IP checks, fixed
base URL) is an edit to the tool's own source.

**Confidence 0.6:**
Matches the Python sibling's 0.6. False positives: a tool that fetches a
parameter-supplied URL but validates it in a helper in another module still fires,
since the fact sees only the handler body's first argument; the fact also cannot
tell a genuinely public "fetch this page" tool from an internal one. False
negatives that are TS-specific: an HTTP client not in the recognized callee set
(`http.request`, `https.get`, `node-fetch` under a renamed import,
`XMLHttpRequest`, a `new URL(...)` passed positionally), a URL placed in an options
object rather than the first positional argument (`axios({ url })`,
`fetch(req)` where `req` is a `Request`), or a URL assembled in a helper, all
evade the first-argument check.

### CSDK-024 — Claude SDK tool fetches an allow-listed host without pinning https:// (Severity: medium, Confidence: 0.6, Fix type: code)

**What we detect:** a Python tool whose body checks the destination host against a named allow-list (the same `has_body_text` credit that silences CSDK-009) and makes a recognized HTTP call (`requests`/`httpx`/`urllib`/aliased clients) with a dynamic URL that neither starts with a literal `https://` prefix nor is guarded by a scheme check (`.scheme ==`/`!=`/`in`/`not in`, `startswith("https://")`). Backed by `has_unpinned_scheme_url_call`, which treats an f-string, `+` concatenation, `%`-format, or `.format()` call whose leftmost literal starts with `https://` as pinned.

**Why it is flaggable:** the allow-list (CSDK-009's credit) constrains *where* the request goes, not *how*. An `http://` URL for an allowed
host passes the host check, so request headers (API keys, bearer tokens) and bodies travel in cleartext, and a network-path attacker can read
them or rewrite the response. The response re-enters the model's context as trusted tool output, which makes tampering a prompt-injection channel.
A redirect from the allowed host to `http://` has the same effect.

**Real-world consequence:** credential and data disclosure to anyone on the network path (shared Wi-Fi, compromised proxy, hostile egress hop)
and integrity loss of the content the model reasons over.

**Why medium / 0.6:** medium rather than CSDK-009's high because the host is already bounded, so the residual risk needs a network-path attacker
rather than just a prompt injection. Confidence is 0.6 because the scheme may be enforced where this rule cannot see it: a helper defined in
another function or module, a base URL configured on a client object, or a prefix built on an earlier line and passed by identifier.

**Staging:** the rule requires the allow-list credit to be present, so CSDK-009 and CSDK-024 never fire on the same tool: SSRF first, then HTTPS once a host
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

### CSDK-025 — TypeScript Claude SDK tool fetches an allow-listed host without pinning https:// (Severity: medium, Confidence: 0.6, Fix type: code)

**What we detect:** a TypeScript tool whose body checks `.hostname`/`.host` against an allow-list (the positive form of the credit that silences CSDK-013) and calls `fetch`/`axios`/`got`/`undici` with a dynamic URL that neither starts with a literal `https://` prefix nor is guarded by a `.protocol` comparison or `startsWith("https:")`. Backed by the `url_scheme_unpinned` handler fact computed beside `dynamic_url`; a template string or `+` concatenation whose leftmost fragment is a literal `https://` is treated as pinned.

**Why it is flaggable:** the allow-list (CSDK-013's credit) constrains *where* the request goes, not *how*. An `http://` URL for an allowed
host passes the host check, so request headers (API keys, bearer tokens) and bodies travel in cleartext, and a network-path attacker can read
them or rewrite the response. The response re-enters the model's context as trusted tool output, which makes tampering a prompt-injection channel.
A redirect from the allowed host to `http://` has the same effect.

**Real-world consequence:** credential and data disclosure to anyone on the network path (shared Wi-Fi, compromised proxy, hostile egress hop)
and integrity loss of the content the model reasons over.

**Why medium / 0.6:** medium rather than CSDK-013's high because the host is already bounded, so the residual risk needs a network-path attacker
rather than just a prompt injection. Confidence is 0.6 because the scheme may be enforced where this rule cannot see it: a helper defined in
another function or module, a base URL configured on a client object, or a prefix built on an earlier line and passed by identifier.

**Staging:** the rule requires the allow-list credit to be present, so CSDK-013 and CSDK-025 never fire on the same tool: SSRF first, then HTTPS once a host
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

## Allow-list credit

CSDK-009, CSDK-013 used to fire on every non-literal destination, including tools that had already constrained the host, which made the rule a false-positive source for exactly the code that followed its own fix advice. The match is now `has_dynamic_url_call` **and not** a recognized host allow-list in the tool body. Severity, confidence and scope are unchanged.

**Python (CSDK-009).** The rule is silenced when the function body contains a hostname membership test against a named allow-list: `.hostname not in`, `.netloc not in`, or one of `ALLOWED_HOSTS`, `ALLOWED_DOMAINS`, `allowed_hosts`, `allowed_domains`, `HOST_ALLOWLIST`, `host_allowlist` (predicate `not: has_body_text`). A bare `.hostname in` is deliberately *not* credited, because it cannot tell an allow-list from a deny-list.

**TypeScript (CSDK-013).** The rule is silenced when the handler both reads a host (`.hostname` / `.host`) and tests membership (`.includes(` / `.has(`), or references a named allow-list (`allowedHosts`, `allowedDomains`, `ALLOWED_HOSTS`, `ALLOWED_DOMAINS`, `hostAllowlist`). Reading `new URL(x).hostname` with no membership test does not silence it.

The credit is textual and body-local. It does not verify that the allow-list is correct, that the check runs before the request, or that the request cannot be redirected to a host outside it; HTTPS-only enforcement and a redirect cap are recommended in each rule's fix text but are not separately detected.

---

## What this policy does not cover

- URL validation implemented in another module or via a decorator — the body walk
  sees only the tool function, so a guarded tool may still fire (false positive).
- `urllib.request.urlopen`, `aiohttp`, `urllib3`, and raw `socket` connections
  with dynamic targets — not in the recognized HTTP-call set today.
- A literal base URL combined with a model-controlled *path* that uses `..` or an
  `@`-userinfo trick to redirect to another host.
- DNS rebinding and redirect-based SSRF (first request to an allowed host that
  302s to an internal address).
- Whether the fetched content is itself dangerous (prompt injection in the
  response body) — an output-guardrail concern, not this rule.
- (TypeScript, CSDK-013) HTTP clients outside the recognized callee set —
  `http.request` / `https.get`, `node-fetch` under a renamed import,
  `XMLHttpRequest`, and `superagent` — do not fire. A model-controlled URL passed
  in an options object (`axios({ url })`) rather than as the first positional
  argument also evades the first-argument check.
- An allow-list enforced in a helper or middleware outside the tool body, an allow-list check that uses a name outside the recognized set, and a membership test that is unrelated to the URL host but happens to sit beside a `.host` read (TypeScript over-credit). Redirects and non-HTTPS schemes are not detected.

---

## Recommendations beyond the fix

```python
import ipaddress
import socket
from urllib.parse import urlparse

import httpx
from claude_agent_sdk import tool

_ALLOWED_HOSTS = {"api.example.com", "data.example.com"}

@tool
def fetch_report(host: str, path: str) -> dict:
    """Fetch a report from an approved host. `host` must be on the allow-list."""
    if host not in _ALLOWED_HOSTS:
        return {"error": "host not allowed", "retryable": False}
    for info in socket.getaddrinfo(host, 443):
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return {"error": "host resolves to a non-public address", "retryable": False}
    url = f"https://{host}/{path.lstrip('/')}"
    if urlparse(url).hostname != host:
        return {"error": "constructed URL host mismatch", "retryable": False}
    return {"body": httpx.get(url, timeout=10, follow_redirects=False).text}
```

1. Make the **host** an allow-list, not the path — the host is the security
   boundary; a path-only allow-list is bypassable via userinfo/redirect tricks.
2. Resolve the hostname and reject private, loopback, link-local, and reserved IP
   ranges *before* connecting, re-checking after any redirect.
3. Disable automatic redirects so an allowed host cannot bounce the request to an
   internal address.
4. At the agent/host level, block `169.254.169.254` and internal CIDRs at the
   network layer as defense in depth.
5. For MCP tools, treat the URL parameter as fully hostile regardless of
   deployment, since the caller is an external orchestrator.
