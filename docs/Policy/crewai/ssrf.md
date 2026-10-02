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
  - id: CREW-015
    severity: medium
    confidence: 0.6
    scope: tool
    fix_type: code
references: [LLM06, LLM02, LLM01]
---

# Policy Rationale: CrewAI SSRF Safety

**Policy ID:** `crewai_ssrf`  
**File:** `crewai/ssrf.yaml`  
**Rules:** CREW-005, CREW-015  
**Severities:** high, medium  
**Fix types:** code, code  
**References:** LLM06 (Excessive Agency), LLM02, LLM01

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

### CREW-015 — CrewAI tool fetches an allow-listed host without pinning https:// (Severity: medium, Confidence: 0.6, Fix type: code)

**What we detect:** a Python tool whose body checks the destination host against a named allow-list (the same `has_body_text` credit that silences CREW-005) and makes a recognized HTTP call (`requests`/`httpx`/`urllib`/aliased clients) with a dynamic URL that neither starts with a literal `https://` prefix nor is guarded by a scheme check (`.scheme ==`/`!=`/`in`/`not in`, `startswith("https://")`). Backed by `has_unpinned_scheme_url_call`, which treats an f-string, `+` concatenation, `%`-format, or `.format()` call whose leftmost literal starts with `https://` as pinned.

**Why it is flaggable:** the allow-list (CREW-005's credit) constrains *where* the request goes, not *how*. An `http://` URL for an allowed
host passes the host check, so request headers (API keys, bearer tokens) and bodies travel in cleartext, and a network-path attacker can read
them or rewrite the response. The response re-enters the model's context as trusted tool output, which makes tampering a prompt-injection channel.
A redirect from the allowed host to `http://` has the same effect.

**Real-world consequence:** credential and data disclosure to anyone on the network path (shared Wi-Fi, compromised proxy, hostile egress hop)
and integrity loss of the content the model reasons over.

**Why medium / 0.6:** medium rather than CREW-005's high because the host is already bounded, so the residual risk needs a network-path attacker
rather than just a prompt injection. Confidence is 0.6 because the scheme may be enforced where this rule cannot see it: a helper defined in
another function or module, a base URL configured on a client object, or a prefix built on an earlier line and passed by identifier.

**Staging:** the rule requires the allow-list credit to be present, so CREW-005 and CREW-015 never fire on the same tool: SSRF first, then HTTPS once a host
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
