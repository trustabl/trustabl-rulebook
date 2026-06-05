---
policy_id: autogen_ssrf
category: autogen
topic: ssrf
rules:
  - id: AG2-011
    severity: high
    confidence: 0.8
    scope: tool
    fix_type: code
references: [LLM06]
---

# Policy Rationale: AutoGen SSRF Safety

**Policy ID:** `autogen_ssrf`  
**File:** `autogen/ssrf.yaml`  
**Rules:** AG2-011  
**Severities:** high  
**Fix types:** code  
**References:** LLM06 (Excessive Agency)

---

## What this policy covers

AutoGen tool function bodies that issue an outbound HTTP request to a non-literal
URL. **AG2-011** uses the `has_dynamic_url_call` predicate: a request call
(`requests.*`, `httpx.*`, `urllib`, an aiohttp session, …) whose URL argument is
built from a parameter, an f-string, or a concatenation rather than a fixed
string literal. A request to a hard-coded constant URL does not fire.

---

## Why SSRF is a distinct concern in AutoGen tools

When the request URL is a literal, the developer chose the destination. When it
is built from a tool argument, the *model* chooses the destination at call time —
and in an AutoGen agent the model's choices are reachable by prompt injection. A
server-side request originates from inside the agent's network, so it can reach
things an external caller cannot: internal services on private CIDRs, localhost
admin ports, and the cloud metadata endpoint (169.254.169.254) that hands out
short-lived IAM credentials. A single injected instruction that redirects the
fetch to the metadata endpoint exfiltrates those credentials through the model's
next output.

There is a second-order hazard specific to agents: whatever the tool fetches
re-enters the conversation as text the model reads, so an attacker who controls
the fetched page controls a fresh prompt-injection channel into the agent. The
SSRF primitive is therefore both an outbound credential-theft path and an inbound
injection path at once — excessive agency (LLM06) even when the developer never
intended the tool to reach internal hosts.

---

## Rule-by-rule defense

### AG2-011 — Tool fetches a caller-controlled URL (Severity: high, Confidence: 0.8, Fix type: code)

**What we detect:** an AutoGen tool body that issues an HTTP request whose URL is
non-literal — built from a parameter or interpolated value (predicate
`has_dynamic_url_call`).

**Why it is flaggable:** a model-controlled request target lets a prompt injection
point the request at internal services or the metadata endpoint, and feeds the
response back into the conversation as untrusted text.

**Real-world consequence:** a `fetch(url)` tool calling `requests.get(url)` is
injected with `url="http://169.254.169.254/latest/meta-data/iam/security-credentials/role"`;
the returned credentials are exfiltrated through the model's next reply.

**Why severity is high and not critical:** SSRF is serious but its blast radius
depends on the host's network position (a host with no reachable internal
services or metadata endpoint gets far less); it is not the unconditional code
execution the engine reserves critical for. **Fix type — code:** constraining or
hard-coding the destination is an edit to the tool body. **Confidence 0.8:** the
predicate flags a non-literal URL, so it over-fires when the dynamic part is
already validated against an allow-list inside the body (the rule cannot see the
guard), and under-fires when the URL is assembled in a helper in another module.

---

## What this policy does not cover

- A request whose URL is dynamic but already validated against an allow-list
  inside the tool body — the rule cannot see the guard, so it fires anyway (a
  known false positive).
- A fetch assembled in a helper in another module — the body-only walk misses it.
- DNS-rebinding and time-of-check/time-of-use attacks against an allow-list that
  validates the hostname but not the resolved IP. Defeating those requires
  re-checking the resolved address.
- Exfiltration or internal access through non-HTTP primitives (raw sockets, DNS,
  SMTP) belongs to other concerns.
- Missing-timeout on the same request is a separate reliability rule
  (**AG2-012**, network.md).

---

## Recommendations beyond the fix

```python
import ipaddress, socket
from urllib.parse import urlparse
import requests

ALLOWED_HOSTS = {"api.example.com"}

def get_status(path: str) -> str:
    """Fetch a status path from the vetted API host only."""
    url = f"https://api.example.com/{path.lstrip('/')}"   # host is fixed
    host = urlparse(url).hostname
    if host not in ALLOWED_HOSTS:
        return "error: host not allowed"
    ip = ipaddress.ip_address(socket.gethostbyname(host))
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return "error: resolves to a non-public address"
    return requests.get(url, timeout=10).text
```

1. If the tool only ever talks to one service, hard-code the base URL and accept
   only a path or query from the model — never a full URL.
2. When a host must be dynamic, validate it against an allow-list, resolve the
   hostname, and re-check the resolved IP against private / loopback / link-local
   ranges to defeat DNS rebinding.
3. Disable or constrain redirect following so a 302 cannot bounce the request
   into an internal address, and always pass `timeout=`.
4. Treat the fetched body as untrusted — keep it out of the system prompt and do
   not let it expand the agent's permissions.
