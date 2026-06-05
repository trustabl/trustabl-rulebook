---
policy_id: crewai_ssrf
category: crewai
topic: ssrf
rules:
  - id: CREW-005
    severity: high
    confidence: 0.8
    scope: tool
    fix_type: code
references: [LLM06]
---

# Policy Rationale: CrewAI SSRF Safety

**Policy ID:** `crewai_ssrf`  
**File:** `crewai/ssrf.yaml`  
**Rules:** CREW-005  
**Severities:** high  
**Fix types:** code  
**References:** LLM06 (Excessive Agency)

---

## What this policy covers

CrewAI `@tool`-decorated function bodies that issue an outbound HTTP request to a
non-literal URL. The detection is the `has_dynamic_url_call` predicate: a request
call (`requests.*`, `httpx.*`, `urllib`, an aiohttp session, …) whose URL
argument is built from a parameter, an f-string, or a concatenation rather than a
fixed string literal. A request to a hard-coded constant URL does not fire.

This rule covers SSRF reached by *hand-rolled* fetches inside a tool body. The
model-chosen URLs of CrewAI's built-in scraper / RAG tools are a separate
agent-scope concern (CREW-107, dangerous_tools.md).

---

## Why SSRF is a distinct concern in CrewAI tools

When the request URL is a literal, the developer chose the destination. When it
is built from a tool argument, the *model* chooses the destination at call time —
and in a CrewAI agent the model's choices are reachable by prompt injection. A
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
injection path at once — which is why a model-controlled request target is
excessive agency (LLM06) even when the developer never intended the tool to reach
internal hosts.

---

## Rule-by-rule defense

### CREW-005 — Tool fetches a caller-controlled URL (Severity: high, Confidence: 0.8, Fix type: code)

**What we detect:** a CrewAI `@tool` body that issues an HTTP request whose URL
is non-literal — built from a parameter or interpolated value (predicate
`has_dynamic_url_call`).

**Why it is flaggable:** a model-controlled request target lets a prompt
injection point the request at internal services or the metadata endpoint, and
feeds the response back into the conversation as untrusted text.

**Real-world consequence:** a `fetch_url(url)` tool calling `requests.get(url)` is
injected with `url="http://169.254.169.254/latest/meta-data/iam/security-credentials/role"`;
the returned credentials are exfiltrated through the model's next reply.

**Why severity is high and not critical:** SSRF is serious but its blast radius
depends on the host's network position (a host with no reachable internal
services or metadata endpoint gets far less); it is not the unconditional code
execution the engine reserves critical for. **Fix type — code:** constraining or
hard-coding the destination is an edit to the tool body. **Confidence 0.8:** the
predicate flags a non-literal URL, so it over-fires when the dynamic part is
already validated against an allow-list inside the body (the rule cannot see the
guard), and it under-fires when the URL is assembled in a helper in another
module.

---

## What this policy does not cover

- The model-chosen URLs of CrewAI's built-in scraper / search / RAG tools — those
  are flagged at agent scope by **CREW-107** (dangerous_tools.md).
- A request whose URL is dynamic but already validated against an allow-list
  inside the tool body — the rule cannot see the guard, so it fires anyway (a
  known false positive).
- A fetch assembled in a helper in another module — the body-only walk misses it.
- DNS-rebinding and time-of-check/time-of-use attacks against an allow-list that
  validates the hostname but not the resolved IP. Defeating those requires
  re-checking the resolved address, which is beyond what this rule asserts.
- Exfiltration or internal access through non-HTTP primitives (raw sockets, DNS,
  SMTP) belongs to other concerns.

---

## Recommendations beyond the fix

```python
from crewai.tools import tool
import ipaddress, socket
from urllib.parse import urlparse
import requests

ALLOWED_HOSTS = {"api.example.com"}

@tool("get_status")
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
   into an internal address.
4. Always pass `timeout=`, and treat the fetched body as untrusted — keep it out
   of the system prompt and do not let it expand the agent's permissions.
