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
**Severities:** high, high, medium, medium  
**Fix types:** code, code, code, code  
**References:** LLM06 (Excessive Agency), LLM02 (Sensitive Information Disclosure), LLM01 (Prompt Injection)

> Shares the SSRF threat model with [claude_sdk/ssrf.md](../claude_sdk/ssrf.md).
> This document covers the MCP-specific mechanism: the destination is chosen by
> a model reading untrusted content, so the attacker never needs to reach the
> server directly.

---

## What this policy covers

MCP tool handlers that issue an outbound HTTP request whose destination URL is
not a fixed string literal. The match is a single predicate,
`has_dynamic_url_call: true`, evaluated against the handler. MCP-008 covers
Python handlers using `requests`, `httpx`, or `urllib`; MCP-013 covers
TypeScript handlers using `fetch`, `axios`, `got`, or `undici`, via the captured
`dynamic_url` handler fact. Both fire on the same shape: the URL argument is a
parameter, an interpolated or template string, an identifier, or a
concatenation, rather than a literal written into the source.

---

## Why SSRF is a distinct concern in agent tools

SSRF is not new and the mechanism is not agent-specific. What changes under MCP
is who supplies the destination and how they reach it.

In a conventional web application the untrusted URL arrives from a request an
attacker sent. There is a person or a script on the other end of a socket, and
the boundary is visible in the code: this parameter came from outside, therefore
distrust it. Input validation sits at that boundary because everyone knows where
the boundary is.

Under MCP the tool argument is filled in by the model, and the model fills it in
from whatever is currently in its context. That context is assembled from
sources the tool author does not control: a fetched web page, an uploaded
document, an email body, a repository issue, the output of an earlier tool call.
An attacker who can place text into any of those sources can influence what the
model passes to this tool. They never open a connection to the MCP server. They
write something a model will later read.

That makes this a confused-deputy problem rather than an input-validation
problem. The MCP server holds a network position the attacker does not: it sits
inside a VPC, on a host with an instance role, with routes to loopback admin
interfaces and internal service addresses that are unreachable from the public
internet. The model has that network position by proxy and the attacker's
intent by injection, and it cannot distinguish the two, because instructions and
data arrive through the same channel and look identical to it. The tool then
executes faithfully. Every layer behaves exactly as designed and the request
still goes somewhere it should not.

The consequences follow from where the server can reach. Cloud metadata
endpoints such as `169.254.169.254` vend short-lived credentials for the host's
instance role to anything that asks from on-box; a tool that will fetch an
arbitrary URL will fetch that and return the response into the conversation.
That is LLM06 (Excessive Agency), the agent acting beyond its intended
authority, and LLM02 (Sensitive Information Disclosure), because the fetched
body crosses back over the trust boundary into context the attacker may be able
to read or exfiltrate through a later tool call. A tool that also forwards a
request body compounds it: the body is sent to the attacker's chosen host, so
the same call both reads internal state and leaks whatever it was carrying.

---

## Rule-by-rule defense

### MCP-008 — Tool fetches a caller-controlled URL (SSRF) (Severity: high, Confidence: 0.6, Fix type: code)

**What we detect:**  
A Python MCP handler (`applies_to: mcp_tool`, `language: python`) containing an
HTTP call through `requests`, `httpx`, or `urllib` where the URL argument is not
a string literal. A parameter passed straight through, an f-string, a `+`
concatenation, or a variable assigned earlier all satisfy the predicate. There
is no callee allow-list and no taint tracking: the check is structural on the
shape of the URL expression, not on where its value came from.

**Why it is flaggable:**  
A literal URL can only ever reach the host the author wrote down. A non-literal
one can reach whatever the caller supplies, and under MCP the caller is a model
reading content the author does not control. The absence of a literal is
therefore the point at which the destination stops being a property of the code
and starts being a property of the conversation.

**Real-world consequence:**

- A `fetch_url(url)` research tool is given a link harvested from a page the
  model was asked to summarize. The page contains injected text instructing the
  model to fetch a link-local address; the handler returns instance credentials
  into the transcript.
- A `check_webhook(endpoint)` tool is pointed at a loopback admin API bound to
  `127.0.0.1` and assumed unreachable, because on this host it is reachable and
  the tool is running on this host.
- A `post_report(url, payload)` tool that forwards a body sends internal data to
  an attacker-chosen host, turning the same call into both a read and an
  exfiltration path.

**Why severity is high and not medium:**  
The credential case has no partial mitigation once it fires. A metadata response
returned into context is a live credential in a place the attacker may be able
to reach, and it is valid immediately. The rule cannot know whether a given tool
has that reachability, so it is calibrated for the environment where MCP servers
are usually deployed, which is on a host with an instance role. Medium would
imply a precondition that reliably caps the damage, and there is none here that
the tool author controls from inside the handler.

**Fix type — code:**  
The destination must be constrained inside the handler: an allow-list check, an
IP-range rejection after DNS resolution, or resolving an opaque identifier
against a server-side registry. No host configuration, sandbox policy, or agent
constructor parameter can restrict a URL that the tool itself constructs and
fetches.

**Confidence 0.6:**  
The low confidence is the cost of the predicate being purely structural. It
detects "this URL is not a literal", which is a much wider set than "this URL is
attacker-controlled". **False positives:** a fixed base with a dynamic path
segment (`requests.get(f"https://api.internal/v1/users/{user_id}")`) is not
SSRF, because the host cannot move, and the rule cannot tell a moving host from
a moving path. A URL read from configuration or an environment variable is
author-controlled and still fires. A handler that already validates against an
allow-list or rejects private ranges before the call fires anyway, because the
rule does not read guard logic. **False negatives:** a literal URL passed to a
client configured with a caller-controlled `base_url` moves the destination
without moving the literal. A handler that delegates the fetch to a helper in
another module has no dynamic URL call at the handler level to detect.

---

**Real-world consequence:** a summarizing server runs in a VPC and exposes
`fetch_page(url)`. A document in the conversation instructs the model to fetch
`http://169.254.169.254/latest/meta-data/iam/security-credentials/`. The handler
does, because that is its job, and returns the body as the tool result — the
instance's role credentials, delivered into the conversation. The attacker never
needed access to the VPC; they needed the server to make one request on their
behalf, from a network position they do not have and the server does.

**Real-world consequence:** a stale, forgotten-but-still-live internal system — one that was supposed to be decommissioned but never was, with credentials for it sitting in an accessible file — is a plausible SSRF target: nobody is watching it, so a steered request against it goes unnoticed until data is already gone. The consequence isn't always data theft, either. In one publicly-relevant case, an attacker used an internal foothold to lock a company and its customers out of a cloud-hosted system entirely — no data was actually accessed (so it wasn't a reportable breach), but the business couldn't operate until a ransom was paid. An SSRF-reachable internal endpoint is a plausible entry point for that class of availability attack, not only for credential exfiltration.

### MCP-013 — TypeScript MCP tool fetches a caller-controlled URL (SSRF) (Severity: high, Confidence: 0.6, Fix type: code)

**What we detect:**  
The same predicate against a TypeScript handler (`language: typescript`): a
`fetch`, `axios`, `got`, or `undici` call whose URL argument is a template
literal, an identifier, or a concatenation rather than a string literal,
recorded as the `dynamic_url` handler fact.

**Why it is flaggable:**  
Identical to MCP-008. The rule is split by language because the analyzer parses
Python and TypeScript separately, not because the threat differs.

**Real-world consequence:**  
As MCP-008. One TypeScript-specific note: `fetch` follows redirects by default
unless `redirect: "manual"` is set, so a handler that validates the initial host
correctly can still be walked to an internal address by a redirect from a host
that passed the check.

**Why severity is high and not medium:**  
As MCP-008. The network position of the server is what sets the ceiling, and
that is a property of the deployment, not of the language the handler is written
in.

**Fix type — code:**  
As MCP-008.

**Confidence 0.6:**  
As MCP-008, with the same structural limitation. **TypeScript-specific false
positive:** a template literal with a fixed host and an interpolated path
(`` fetch(`https://api.internal/v1/users/${id}`) ``) is a very common idiom and
fires without the host being movable. This shape is idiomatic enough in
TypeScript that it is likely the dominant false positive for MCP-013.
**TypeScript-specific false negative:** an `axios` instance created with
`axios.create({ baseURL })` where `baseURL` is caller-supplied, then called with
a literal path, moves the destination while every call site still shows a
literal.

**Real-world consequence:** identical to MCP-008, with one TypeScript-specific
path in. `fetch` follows redirects by default, so a handler that allow-lists the
host it is given still reaches the metadata endpoint if the allowed host answers
with a 302 pointing at it. The check ran, passed, and protected nothing —
`redirect: "manual"` is what closes it.

**Real-world consequence:** same consequence class as MCP-008 — stale internal systems and availability/ransom attacks are language-agnostic outcomes of a successful SSRF, not specific to the Python SDK.

---

## Allow-list credit

MCP-008, MCP-013 used to fire on every non-literal destination, including tools that had already constrained the host, which made the rule a false-positive source for exactly the code that followed its own fix advice. The match is now `has_dynamic_url_call` **and not** a recognized host allow-list in the tool body. Severity, confidence and scope are unchanged.

**Python (MCP-008).** The rule is silenced when the function body contains a hostname membership test against a named allow-list: `.hostname not in`, `.netloc not in`, or one of `ALLOWED_HOSTS`, `ALLOWED_DOMAINS`, `allowed_hosts`, `allowed_domains`, `HOST_ALLOWLIST`, `host_allowlist` (predicate `not: has_body_text`). A bare `.hostname in` is deliberately *not* credited, because it cannot tell an allow-list from a deny-list.

**TypeScript (MCP-013).** The rule is silenced when the handler both reads a host (`.hostname` / `.host`) and tests membership (`.includes(` / `.has(`), or references a named allow-list (`allowedHosts`, `allowedDomains`, `ALLOWED_HOSTS`, `ALLOWED_DOMAINS`, `hostAllowlist`). Reading `new URL(x).hostname` with no membership test does not silence it.

The credit is textual and body-local. It does not verify that the allow-list is correct, that the check runs before the request, or that the request cannot be redirected to a host outside it; HTTPS-only enforcement and a redirect cap are recommended in each rule's fix text but are not separately detected.

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

- **Whether the dynamic value is genuinely attacker-reachable.** The predicate is
  structural. A URL assembled from an environment variable, a config file, or a
  constant in another module is author-controlled and fires identically to one
  built from a tool argument.
- **A fixed host with a dynamic path.** The most common safe shape is
  indistinguishable from the unsafe one at this level of analysis, and it is the
  main reason confidence sits at 0.6 rather than higher.
- **Validation the rule cannot see.** An allow-list check, a
  `ipaddress.ip_address(...).is_private` rejection, or a registry lookup before
  the call all leave the call site unchanged, so a correctly guarded handler
  still fires.
- **Redirect-based SSRF.** A request to an allowed host that returns a redirect
  to an internal address defeats a host check performed before the call. Python
  `requests` and TypeScript `fetch` both follow redirects by default.
- **DNS rebinding.** A hostname that resolves to a public address during
  validation and to an internal one when the request is issued passes any check
  performed at validation time. Nothing at the call site can detect this.
- **Base-URL indirection.** `httpx.Client(base_url=...)` or
  `axios.create({ baseURL })` with a caller-supplied base moves the destination
  while every call site retains a string literal.
- **Clients outside the recognized set.** Raw sockets, `http.client`, `urllib3`
  used directly, gRPC, and vendored SDK clients that accept a configurable
  endpoint are not inspected.
- **Non-HTTP destinations.** A database connection string, a message broker
  address, or a file URL built from a tool argument reaches internal services by
  the same logic and is out of scope for this policy.
- **What is done with the response.** Returning a fetched body into the
  conversation is what completes the disclosure path, and that is not part of
  this predicate.
- **Allow-list credit is textual.** An allow-list enforced in a helper or
  middleware outside the tool body, or checked under a name outside the
  recognized set (see Allow-list credit), is not credited and still fires. In
  TypeScript, a membership test unrelated to the URL host that sits beside a
  `.host` read over-credits and silences the rule. Redirects and non-HTTPS
  schemes are not detected.
  
---

## Recommendations beyond the fix

```python
import ipaddress
import socket
from urllib.parse import urlparse

import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fetcher")

ALLOWED_HOSTS = {"api.example.com", "docs.example.com"}


def _resolved_addresses(hostname: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Every address the hostname resolves to, so a multi-record host cannot
    hide an internal address behind a public one."""
    infos = socket.getaddrinfo(hostname, None)
    return [ipaddress.ip_address(info[4][0]) for info in infos]


@mcp.tool()
def fetch_url(url: str) -> dict:
    """Fetch an allow-listed URL. The host must be on the allow-list and must
    not resolve to a private, loopback, or link-local address. Redirects are
    not followed, so an allowed host cannot forward the request inward."""
    parsed = urlparse(url)

    if parsed.scheme != "https":
        return {"ok": False, "error": "scheme_not_allowed", "scheme": parsed.scheme}

    if parsed.hostname not in ALLOWED_HOSTS:
        return {"ok": False, "error": "host_not_allowed", "host": parsed.hostname}

    try:
        addresses = _resolved_addresses(parsed.hostname)
    except socket.gaierror:
        return {"ok": False, "error": "dns_failure", "host": parsed.hostname}

    for address in addresses:
        if address.is_private or address.is_loopback or address.is_link_local or address.is_reserved:
            return {"ok": False, "error": "address_not_allowed"}

    try:
        response = httpx.get(url, timeout=10.0, follow_redirects=False)
    except httpx.TimeoutException:
        return {"ok": False, "error": "timeout"}

    if response.is_redirect:
        return {"ok": False, "error": "redirect_not_followed"}

    return {"ok": True, "status": response.status_code, "text": response.text}
```

1. Prefer an opaque identifier over a URL. If the tool can accept a document ID
   or a source name and look the real URL up in a server-side registry, the
   model never supplies a destination at all and the entire class disappears.
   An allow-list is the fallback for when a free-form URL is genuinely required.
2. Disable redirects rather than validating and then following them. Checking
   the host before the request and following redirects afterwards validates one
   destination and fetches another.
3. Resolve and check every address the hostname returns, not just the first.
   A host with both a public and a private record passes a single-address check.
4. Do not return raw response bodies into the conversation when the destination
   is dynamic. Extract and return the specific fields the tool exists to
   provide, so a response the tool did not expect cannot become context.
5. Run the MCP server without an instance role where possible, and block
   link-local egress at the network layer. This does not satisfy the rule,
   because the fix type is `code`, but it caps the damage when a handler is
   missed.
6. Set an explicit timeout on the call. An SSRF-constrained handler that hangs
   is still a stalled session (see MCP-004).
