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

# Policy Rationale: Server-Side Request Forgery

**Policy ID:** `mcp_ssrf`  
**File:** `mcp/ssrf.yaml`  
**Rules:** MCP-008, MCP-013  
**Severities:** high, high  
**Fix types:** code, code  
**References:** LLM06, LLM02

> **Read [claude_sdk/ssrf.md](../claude_sdk/ssrf.md) for the canonical SSRF threat model.**
> This document covers the MCP-specific differences only — chiefly *who* controls
> the URL argument (a remote orchestrator's model, never a human) and *where* the
> MCP server sits on the network.

---

## What this policy covers

MCP tool handlers — functions registered via `@server.tool` / `@mcp.tool` /
`.register_tool` (Python, MCP-008) or the TypeScript MCP SDK tool registration
(MCP-013) — whose body issues an HTTP request to a destination URL that is not a
fixed string literal. Detection is the structured `has_dynamic_url_call`
predicate, not a substring scan. On the **Python** side it walks the handler's
AST, resolves same-function client aliases (`s = requests.Session(); s.get(...)`),
recognizes a fixed set of HTTP callees — the `requests` family
(`requests.get/post/put/delete/patch/head/request`, `requests.Session.get/post`),
the `httpx` family (`httpx.get/post/put/delete/patch/head/request` plus
`httpx.Client` / `httpx.AsyncClient`), `urllib.request.urlopen`, and
`aiohttp.ClientSession.get/post` — and fires when the first positional argument is
anything other than a plain string literal: a bare parameter (`requests.get(url)`),
an f-string with an `interpolation` child (`httpx.get(f"https://{host}/x")`), or a
built-up expression. On the **TypeScript** side the signal is the discovery-computed
`dynamic_url` fact: it recognizes the callees `fetch`, `axios`
(`axios.get/post/put/delete/patch/request`), `got` (`got.get/post`), and
`undici.fetch` / `undici.request`, inspects the **first positional argument**, and
fires when it is an identifier, a member expression, a concatenation, a call, or a
template string carrying a `${...}` substitution. A request to a hard-coded literal
URL — or a backtick template with no substitution — does not fire on either side.

---

## Why SSRF is a distinct concern in agent tools

The general mechanism — the model picks the destination host, and the agent host
sits inside a cloud network with reach the public internet lacks — is the same one
spelled out in
[claude_sdk/ssrf.md](../claude_sdk/ssrf.md#why-ssrf-is-a-distinct-concern-in-agent-tools).
Read that for the metadata-credential-theft path
(`169.254.169.254` → short-lived role credentials → exfiltration into the model
context and onward into logs or the next turn).

The MCP sharpening is the **trust boundary**, and it is the worst case of the four
SDKs the rulebook covers. An MCP tool's URL argument is not merely "model-chosen"
in the abstract: the arguments arrive over the wire from a *connecting client* the
server does not control, populated by a model that may have been prompt-injected by
untrusted content upstream — a web page it read, a document it summarized, an email
in the thread. There is **no human in the loop** at the moment the tool fires and no
"trusted developer input" channel; the MCP server forwards the client's chosen
arguments verbatim into the HTTP client. A `fetch(target)` handler is, by
construction, a callable the *remote orchestrator* can aim anywhere the server host
can reach.

Where the server sits makes that reach dangerous. MCP servers are routinely
deployed inside a cloud VPC or a CI runner — exactly the environments that expose
the instance metadata service at `169.254.169.254` (vending credentials for the
attached role/service account to any local HTTP caller), loopback admin APIs
(`http://localhost:<port>` dashboards, debug consoles, unauthenticated internal
control planes), and internal-only microservices. A single injected
`fetch("http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>")`
turns prompt injection on the *client* side into credential theft on the *server*
side. Worse than the in-process SDK case, an MCP server is frequently **shared
across multiple clients**: one client's poisoned conversation drives a fetch from a
host that other tenants also rely on, so the SSRF primitive is reachable by the
least-trusted connecting party. The request body — auth headers, payloads — also
leaks to whatever host the URL resolves to.

This maps to OWASP LLM Top 10:2025 **LLM06 (Excessive Agency)** — the tool grants
the connecting model a network reach far broader than its task requires — and
**LLM02 (Sensitive Information Disclosure)**, because the common payoff is
credential or internal-data exfiltration. Allow-listing the *path* while leaving the
*host* caller-controlled is the trap: the host is the security boundary, not the
path.

---

## Rule-by-rule defense

### MCP-008 — Tool fetches a caller-controlled URL (SSRF) (Severity: high, Confidence: 0.6, Fix type: code)

**What we detect:**
A Python MCP tool handler (`@server.tool` / `@mcp.tool` / `.register_tool`) whose
body makes an HTTP call where the URL argument is not a string literal — a
parameter, an interpolated f-string, or a built-up expression. The predicate
(`has_dynamic_url_call`) is an AST walk: it resolves same-function client aliases,
recognizes the `requests.*` / `httpx.*` / `urllib.request.urlopen` /
`aiohttp.ClientSession.get|post` callees, and inspects the first positional
argument, firing when it is anything other than a plain `string` node (an f-string
with an `interpolation` child also fires). Comments and docstrings do not fire.

**Why it is flaggable:**
A non-literal URL in an MCP tool means the destination host is, in practice, chosen
by the connecting client's model. Because MCP arguments cross a trust boundary with
no human gate, the presence of the dynamic URL is the signal that the handler can be
steered at hosts the author never intended — the server is now a confused-deputy
proxy for requests the remote party could not otherwise make.

**Real-world consequence:**
- A `fetch_url(url: str)` tool on an MCP server running in a cloud VPC is, via a
  prompt-injected client conversation, asked to fetch
  `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>`; the
  returned credentials flow back through the tool result into the model context and
  from there into logs or the attacker's next turn.
- A `proxy(target: str)` tool exposed to a desktop MCP client is pointed at
  `http://localhost:<port>` admin services on the host, reaching an internal control
  plane that assumed it was unreachable from any untrusted party.

**Why severity is high and not medium:**
The exploit needs no second vulnerability — a single tool call against a reachable
metadata or internal endpoint yields credentials or internal data, and on MCP there
is no human approval step to interrupt it. It is not critical only because impact is
conditional on the server host's network position, and a correct host allow-list
with post-resolution IP checks fully neutralizes it.

**Fix type — code:**
Constraining the destination — an explicit host allow-list, a fixed base URL with
only a path parameter, or post-resolution rejection of private/loopback/link-local
ranges with redirects disabled — is an edit to the tool's own handler source. A
network-layer egress firewall on the MCP server host is complementary defense in
depth but is not what the rule asks the author to change.

**Confidence 0.6:**
The gap (0.6, well below 0.80) is two-sided. **False positive:** many MCP tools
legitimately fetch a parameter-supplied URL and *do* validate it — but the
validation frequently lives in a helper or an `@`-decorator in another module that
the body-only AST walk cannot see, so a correctly-guarded tool still fires; the
predicate also cannot tell a genuinely public "fetch this page" reader from an
internal proxy. **False negative:** a URL assembled in a helper before the call, or
built via `urljoin`/`urlparse` from a caller-controlled base, or passed to an HTTP
client outside the recognized callee set, evades the first-argument check. A strong
lead to investigate, not a near-certain defect.

### MCP-013 — TypeScript MCP tool fetches a caller-controlled URL (SSRF) (Severity: high, Confidence: 0.6, Fix type: code)

**What we detect:**
A TypeScript MCP tool handler whose body issues an HTTP call to a URL that is not a
plain string literal (predicate `has_dynamic_url_call`, backed by the structural
`dynamic_url` fact computed during discovery). The fact recognizes a fixed set of
HTTP callees — `fetch`, `axios` and its method forms
(`axios.get/post/put/delete/patch/request`), `got` / `got.get` / `got.post`, and
`undici.fetch` / `undici.request` — and inspects the **first positional argument**.
It fires when that argument is an identifier (`fetch(url)`), a member expression
(`fetch(opts.url)`), a string concatenation, a call expression, or a template string
containing a `${...}` substitution. A plain `"https://..."` literal, or a backtick
template with no substitution, does not fire.

**Why it is flaggable:**
A non-literal URL argument means the destination host is chosen by the connecting
client's model. The threat model is identical to the Python sibling
[MCP-008](#mcp-008--tool-fetches-a-caller-controlled-url-ssrf-severity-high-confidence-06-fix-type-code):
the MCP server typically runs inside a VPC or CI runner with reach to the instance
metadata service (`169.254.169.254`), loopback admin endpoints, and internal
microservices the public internet cannot address, and the caller is a remote
orchestrator with no human gate. The only delta is the client library
(`fetch`/`axios`/`got`/`undici` vs Python `requests`/`httpx`/`urllib`/`aiohttp`).

**Real-world consequence:**
- A `readPage(url: string)` MCP web-reader tool, when its connecting client is
  prompt-injected, is asked to fetch
  `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` via
  `fetch(url)`; the returned credentials land in the model context and from there
  into logs or the attacker's next turn.
- An `httpProxy(target: string)` tool on a shared MCP server is steered at a
  tenant-internal admin API at `http://localhost:<port>`, reaching a control plane
  other connected clients depend on.

**Why severity is high and not medium:**
The exploit needs no second vulnerability — one tool call against a reachable
metadata or internal endpoint yields credentials or internal data, with no human
approval step. It is not critical only because impact is conditional on the server
host's network position, and a correct host allow-list fully neutralizes it.
Matches the Python sibling MCP-008.

**Fix type — code:**
Constraining the destination (host allow-list, post-resolution IP checks, fixed base
URL, or resolving an opaque ID against a server-side registry and building the URL
from the trusted entry) is an edit to the tool handler's own source. A VPC egress
policy blocking the metadata CIDR is complementary defense in depth.

**Confidence 0.6:**
Matches the Python sibling's 0.6. **False positives:** a tool that fetches a
parameter-supplied URL but validates it in a helper in another module still fires,
since the fact sees only the handler body's first argument; the fact also cannot
distinguish a genuinely public "fetch this page" tool from an internal proxy.
**False negatives that are TS-specific:** an HTTP client not in the recognized
callee set (`node:http`/`node:https` `request`/`get`, `node-fetch` under a renamed
import, `superagent`, `ky`, `XMLHttpRequest`, or any wrapped client), a URL placed
in an options object rather than the first positional argument (`axios({ url })`,
`fetch(req)` where `req` is a `Request`), a `new URL(base, modelValue)` constructed
before the call, or a URL assembled in a helper — all evade the first-argument check
on a known callee.

---

## What this policy does not cover

- URL validation implemented in another module, a decorator, or a shared helper —
  the body walk sees only the tool handler, so a guarded tool may still fire (false
  positive).
- (Python, MCP-008) HTTP clients outside the recognized set — `urllib3`, `pycurl`,
  `http.client.HTTPConnection`, raw `socket` connections, or `requests`/`httpx`
  calls reached through an instance attribute (`self.client.get(...)`) rather than a
  same-function alias — do not fire.
- (TypeScript, MCP-013) HTTP clients outside the recognized
  `fetch`/`axios`/`got`/`undici` set — `node:http`/`node:https` `request`/`get`,
  `node-fetch` under a renamed import, `superagent`, `ky`, `XMLHttpRequest`, and
  wrapped clients — do not fire. A model-controlled URL passed in an options object
  (`axios({ url })`) or via a `Request` object rather than as the first positional
  argument also evades the check.
- A literal base URL combined with a caller-controlled *path* that uses `..`
  traversal or an `@`-userinfo trick to redirect the request to another host — the
  first argument is a literal, so neither rule fires.
- DNS rebinding and redirect-based SSRF: a first request to an allow-listed host
  that returns a 302 to an internal address. The rules check the *initial* URL, not
  the post-redirect target.
- Indirect destination control: a model-supplied opaque ID or query parameter that
  the handler maps to an internal host through trusted-looking server-side logic.
- Whether the *fetched content* is itself dangerous — prompt injection in the
  response body that flows back into the model — which is an output-guardrail
  concern, not this rule.
- The rules do not weight impact by the server's actual network position or the
  attached role's grants; they treat every dynamic-URL MCP tool as high-impact.
  Treat a finding as high until the server's egress reach and credential blast
  radius are confirmed.

---

## Recommendations beyond the fix

```python
import ipaddress
import socket
from urllib.parse import urlparse

import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("reports")

_ALLOWED_HOSTS = {"api.example.com", "data.example.com"}


@mcp.tool()
def fetch_report(host: str, path: str) -> dict:
    """Fetch a report from an approved host. `host` must be on the allow-list."""
    # 1. Host allow-list — the host is the security boundary, not the path.
    if host not in _ALLOWED_HOSTS:
        return {"error": "host not allowed", "retryable": False}

    # 2. Resolve and reject non-public ranges *before* connecting.
    for info in socket.getaddrinfo(host, 443):
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return {"error": "host resolves to a non-public address", "retryable": False}

    # 3. Build the URL from the trusted host; never let `path` change the host.
    url = f"https://{host}/{path.lstrip('/')}"
    if urlparse(url).hostname != host:
        return {"error": "constructed URL host mismatch", "retryable": False}

    # 4. Disable redirects so an allowed host cannot bounce to an internal one.
    return {"body": httpx.get(url, timeout=10, follow_redirects=False).text}
```

1. Make the **host** an allow-list, not the path — the host is the security
   boundary; a path-only allow-list is bypassable via `..` traversal,
   `@`-userinfo, and redirect tricks.
2. Resolve the hostname and reject private, loopback, link-local, and reserved IP
   ranges *before* connecting, and re-check after every redirect (mitigates DNS
   rebinding, which a one-shot pre-check alone does not).
3. Disable automatic redirects so an allow-listed host cannot bounce the request to
   an internal address.
4. Prefer an **opaque ID resolved against a server-side registry** over a free-form
   URL parameter: accept `report_id`, look up the trusted URL, and never construct
   the destination from the caller's string at all — this removes the dynamic-URL
   signal entirely.
5. Because an MCP server's URL argument arrives from an untrusted remote client with
   no human in the loop, treat it as fully hostile **regardless of deployment**, and
   assume the server may be shared across clients — never widen the allow-list to
   accommodate one client's needs.
6. At the MCP server host / VPC level, block `169.254.169.254` and internal CIDRs at
   the network layer as defense in depth, independent of the tool's own checks.
