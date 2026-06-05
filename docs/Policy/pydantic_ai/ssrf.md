---
policy_id: pydantic_ai_ssrf
category: pydantic_ai
topic: ssrf
rules:
  - id: PYD-005
    severity: high
    confidence: 0.8
    scope: tool
    fix_type: code
references: [LLM06]
---

# Policy Rationale: Pydantic AI SSRF Safety

**Policy ID:** `pydantic_ai_ssrf`  
**File:** `pydantic_ai/ssrf.yaml`  
**Rules:** PYD-005  
**Severities:** high  
**Fix types:** code  
**References:** LLM06 (Excessive Agency)

---

## What this policy covers

Pydantic AI tool function bodies that issue an outbound HTTP request to a
non-literal URL. **PYD-005** uses the `has_dynamic_url_call` predicate: a request
call (`requests.*`, `httpx.*`, `urllib`, an aiohttp session, …) whose URL argument
is built from a parameter, an f-string, or a concatenation rather than a fixed
string literal. A request to a hard-coded constant URL does not fire.

This rule covers SSRF reached by *hand-rolled* fetches inside a tool body. The
model-chosen URLs of Pydantic AI's native `WebFetchTool` / `UrlContextTool` are a
separate agent-scope concern (PYD-103, agent_safety.md).

---

## Why SSRF is a distinct concern in Pydantic AI tools

When the request URL is a literal, the developer chose the destination. When it is
built from a tool argument, the *model* chooses the destination at call time — and
in a Pydantic AI agent the model's choices are reachable by prompt injection. A
server-side request originates from inside the agent's network, so it can reach
what an external caller cannot: internal services on private CIDRs, localhost admin
ports, and the cloud metadata endpoint (169.254.169.254) that hands out short-lived
IAM credentials. A single injected instruction that redirects the fetch to the
metadata endpoint exfiltrates those credentials through the model's next output,
and the fetched body re-enters the conversation as untrusted text — a second-order
injection channel.

Pydantic AI's own history makes the point concrete: its built-in URL fetchers have
had to harden against exactly this class of bug. CVE-2026-46678 and CVE-2026-25580
cover a metadata-endpoint blocklist that could be bypassed — for example via DNS
rebinding or alternate IP encodings — meaning even a fetcher that *tries* to block
internal addresses was evadable. A hand-rolled `requests.get(url)` that does no
validation at all is strictly more exposed than those patched built-ins, which is
why a model-controlled request target is high-severity excessive agency (LLM06).

---

## Rule-by-rule defense

### PYD-005 — Tool fetches a caller-controlled URL (Severity: high, Confidence: 0.8, Fix type: code)

**What we detect:** a Pydantic AI tool body that issues an HTTP request whose URL
is non-literal — built from a parameter or interpolated value (predicate
`has_dynamic_url_call`).

**Why it is flaggable:** a model-controlled request target lets a prompt injection
point the request at internal services or the metadata endpoint, and feeds the
response back into the conversation as untrusted text.

**Real-world consequence:** a `fetch_url(url)` tool calling `requests.get(url)` is
injected with
`url="http://169.254.169.254/latest/meta-data/iam/security-credentials/role"`; the
returned credentials are exfiltrated through the model's next reply — the same
metadata-endpoint vector the SDK's built-in fetchers were patched against
(CVE-2026-46678 / CVE-2026-25580), but with no blocklist at all.

**Why severity is high and not critical:** SSRF is serious but its blast radius
depends on the host's network position (a host with no reachable internal services
or metadata endpoint gets far less); it is not the unconditional code execution the
engine reserves critical for. **Fix type — code:** constraining or hard-coding the
destination is an edit to the tool body. **Confidence 0.8:** the predicate flags a
non-literal URL, so it over-fires when the dynamic part is already validated against
an allow-list inside the body (the rule cannot see the guard), and under-fires when
the URL is assembled in a helper in another module.

---

## What this policy does not cover

- The model-chosen URLs of Pydantic AI's native `WebFetchTool` / `UrlContextTool`
  — those are flagged at agent scope by **PYD-103** (agent_safety.md).
- A request whose URL is dynamic but already validated against an allow-list inside
  the tool body — the rule cannot see the guard, so it fires anyway (a known false
  positive).
- A fetch assembled in a helper in another module — the body-only walk misses it.
- DNS-rebinding and time-of-check/time-of-use attacks against an allow-list that
  checks the hostname but not the resolved IP — the very bypass class the SDK's own
  CVEs describe. The rule flags the unvalidated fetch; it does not verify the
  *quality* of any validation present.
- Exfiltration or internal access through non-HTTP primitives (raw sockets, DNS,
  SMTP) belongs to other concerns.

---

## Recommendations beyond the fix

```python
import ipaddress, socket
from urllib.parse import urlparse
import requests
from pydantic_ai import Agent

agent = Agent("openai:gpt-4o")
ALLOWED_HOSTS = {"api.example.com"}

@agent.tool_plain
def get_status(path: str) -> str:
    """Fetch a status path from the vetted API host only."""
    url = f"https://api.example.com/{path.lstrip('/')}"   # host is fixed
    host = urlparse(url).hostname
    if host not in ALLOWED_HOSTS:
        return "error: host not allowed"
    ip = ipaddress.ip_address(socket.gethostbyname(host))   # re-check resolved IP
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return "error: resolves to a non-public address"
    return requests.get(url, timeout=10, allow_redirects=False).text
```

1. If the tool only ever talks to one service, hard-code the base URL and accept
   only a path or query from the model — never a full URL.
2. When a host must be dynamic, validate it against an allow-list, resolve the
   hostname, and re-check the *resolved IP* against private / loopback / link-local
   ranges — this is the step that defeats the DNS-rebinding bypass the SDK's CVEs
   describe.
3. Disable redirect following (or validate each hop) so a 302 cannot bounce the
   request into an internal address, and always pass `timeout=`.
4. Treat the fetched body as untrusted — keep it out of the system prompt and do
   not let it expand the agent's permissions.
