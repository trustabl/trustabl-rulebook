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
references: [LLM06, LLM02]
---

# Policy Rationale: Server-Side Request Forgery

**Policy ID:** `claude_sdk_ssrf`  
**File:** `claude_sdk/ssrf.yaml`  
**Rules:** CSDK-009, CSDK-013  
**Severities:** high, high  
**Fix types:** code, code  
**References:** LLM06, LLM02

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
