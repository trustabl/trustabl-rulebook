---
policy_id: openai_sdk_ssrf
category: openai_sdk
topic: ssrf
rules:
  - id: OAI-016
    severity: high
    confidence: 0.6
    scope: tool
    fix_type: code
references: [LLM06, LLM02]
---

# Policy Rationale: Server-Side Request Forgery

**Policy ID:** `openai_sdk_ssrf`  
**File:** `openai_sdk/ssrf.yaml`  
**Rules:** OAI-016  
**Severities:** high  
**Fix types:** code  
**References:** LLM06, LLM02

---

## What this policy covers

This policy targets OpenAI Agents SDK `@function_tool` bodies that issue an
outbound HTTP request whose destination URL is not a fixed string literal. The
detection is the structured `has_dynamic_url_call` predicate: it walks the
function's AST, identifies HTTP call sites (the `requests` / `httpx` families
and local client aliases such as `s = requests.Session(); s.get(...)`), and
fires when the URL argument is anything other than a plain literal — a bare
parameter (`requests.get(url)`), an f-string with interpolation
(`httpx.get(f"https://{host}/x")`), or a concatenation. A request to a
hard-coded literal URL does not fire.

---

## Why SSRF is a distinct concern in agent tools

In a conventional web app, the set of URLs a server fetches is fixed by the
developer; SSRF arises only where user input reaches a request unchecked. In an
agent tool the model *is* the caller — it chooses every argument value it passes
to the tool. A tool whose URL comes from a parameter is, by construction, a tool
the model can point anywhere. There is no separate "trusted developer input"
channel; the SDK forwards the model's chosen arguments verbatim.

The damage is not the fetch itself but *where the agent host sits on the
network*. Agent runtimes typically run inside a cloud VPC with reachability the
public internet does not have. The canonical target is the instance metadata
service — `169.254.169.254` on AWS/Azure/GCP — which vends short-lived
credentials for the attached role or service account to any process that can
make a local HTTP request. A single model-driven
`requests.get("http://169.254.169.254/latest/meta-data/iam/security-credentials/...")`
turns prompt injection into cloud credential theft. Beyond metadata, the same
primitive reaches loopback admin endpoints, internal-only microservices, and
link-local addresses — none of which expect to be addressed by an untrusted
party.

This is why SSRF maps to OWASP LLM Top 10:2025 **LLM06 (Excessive Agency)** —
the tool grants the model a network reach far broader than its task requires —
and **LLM02 (Sensitive Information Disclosure)**, because the most common payoff
is credential or internal-data exfiltration. Allow-listing the *path* while
leaving the *host* model-controlled is the trap: the host is the security
boundary, not the path.

---

## Rule-by-rule defense

### OAI-016 — Tool fetches a caller-controlled URL (SSRF) (Severity: high, Confidence: 0.6, Fix type: code)

**What we detect:**
A `@function_tool`-decorated function whose body makes an HTTP call
(`requests.get/post/...`, `httpx.*`, or a resolved session-alias call) where the
first/URL argument is not a string literal — i.e. it is a parameter, an
interpolated f-string, or a built-up expression. The match is an AST walk
(predicate `has_dynamic_url_call`), so a literal URL mentioned in a comment or
docstring does not fire.

**Why it is flaggable:**
A non-literal URL in a model-callable tool means the destination host is, in
practice, chosen by the model. The presence of the dynamic URL is the signal
that the tool can be steered at hosts the author never intended.

**Real-world consequence:**
- A `fetch_url(url: str)` "web reader" tool, when prompt-injected, is asked to
  fetch `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>`;
  the returned credentials land in the model context and from there into logs or
  the next turn.
- A `get_report(host: str)` tool that builds `f"https://{host}/report"` is
  pointed at `localhost:6379` or an internal admin API, letting the model probe
  and read services behind the network boundary.

**Why severity is high and not medium:**
The exploit needs no second vulnerability — a single tool call against a
reachable metadata or internal endpoint yields credentials or internal data.
It is not bumped to critical because impact is conditional on the host's network
position (a tool on a developer laptop with no metadata service is far less
exposed than one on Cloud Run), and a correct host allow-list fully neutralizes
it.

**Fix type — code:**
Constraining the destination (allow-list, fixed base URL, post-resolution IP
checks) is an edit to the tool's own source. An agent-level egress firewall is
complementary but is not what the rule asks for.

**Confidence 0.6:**
False positives: many tools legitimately fetch a URL supplied as a parameter and
*do* validate it — but the validation often lives in a helper in another module
that the body-only AST walk cannot see, so a correctly-guarded tool can still
fire. The predicate also cannot tell a genuinely user-facing "fetch this public
page" tool (lower risk) from an internal one. False negatives: a URL built in a
helper and returned, or assembled from `urllib.parse.urljoin` with a
model-controlled base, can evade the first-argument check. The 0.6 reflects that
this is a strong *lead* to investigate, not a near-certain defect.

---

## What this policy does not cover

- URL validation implemented in another module or via a decorator — the body
  walk sees only the tool function, so a guarded tool may still fire (false
  positive) and a guard that is actually absent looks the same.
- `urllib.request.urlopen`, `aiohttp`, `urllib3`, and raw `socket` connections
  with dynamic targets — not in the recognized HTTP-call set today.
- A literal base URL combined with a model-controlled *path* that uses `..` or
  an `@`-userinfo trick to redirect to another host (`https://trusted.example/@evil.com`).
- DNS rebinding and redirect-based SSRF, where the first request is to an
  allowed host that then 302s to an internal address.
- Whether the fetched content is itself dangerous (prompt injection in the
  response body) — that is an output-guardrail concern, not this rule.

---

## Recommendations beyond the fix

```python
import ipaddress
import socket
from urllib.parse import urlparse

import httpx
from agents import function_tool

_ALLOWED_HOSTS = {"api.example.com", "data.example.com"}

@function_tool
def fetch_report(host: str, path: str) -> dict:
    """Fetch a report from an approved reporting host. `host` must be on the
    allow-list; `path` is appended verbatim."""
    if host not in _ALLOWED_HOSTS:
        return {"error": "host not allowed", "retryable": False}
    # Resolve and reject private / loopback / link-local targets.
    for info in socket.getaddrinfo(host, 443):
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return {"error": "host resolves to a non-public address", "retryable": False}
    url = f"https://{host}/{path.lstrip('/')}"
    if urlparse(url).hostname != host:
        return {"error": "constructed URL host mismatch", "retryable": False}
    return {"body": httpx.get(url, timeout=10, follow_redirects=False).text}
```

1. Make the **host** an allow-list, not the path. The host is the security
   boundary; a path-only allow-list is bypassable via userinfo/redirect tricks.
2. Resolve the hostname and reject private, loopback, link-local, and reserved
   IP ranges *before* connecting — re-checking after any redirect.
3. Disable automatic redirects (`follow_redirects=False`) so an allowed host
   cannot bounce the request to an internal address.
4. At the agent level, place tool egress behind a network policy that blocks
   `169.254.169.254` and the internal CIDR ranges outright — defense in depth
   below the tool.
5. On cloud hosts, prefer credential delivery that does not transit a
   locally-reachable HTTP endpoint (e.g. IMDSv2 with hop-limit 1, or workload
   identity) so a stray SSRF cannot reach the metadata service.
