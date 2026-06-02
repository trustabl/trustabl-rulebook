---
policy_id: google_adk_ssrf
category: google_adk
topic: ssrf
rules:
  - id: ADK-009
    severity: high
    confidence: 0.6
    scope: tool
    fix_type: code
references: [LLM06, LLM02]
---

# Policy Rationale: Server-Side Request Forgery

**Policy ID:** `google_adk_ssrf`  
**File:** `google_adk/ssrf.yaml`  
**Rules:** ADK-009  
**Severities:** high  
**Fix types:** code  
**References:** LLM06, LLM02

> **Read [openai_sdk/ssrf.md](../openai_sdk/ssrf.md) for the full threat model.**
> This document covers Google ADK–specific differences only.

---

## What this policy covers

Google ADK `FunctionTool`-wrapped functions whose body issues an HTTP request to
a non-literal destination URL. Detection is the same `has_dynamic_url_call` AST
predicate described in the OpenAI doc — it fires when the URL argument of a
`requests` / `httpx` call (including resolved session aliases) is a parameter, an
interpolated f-string, or a built-up expression rather than a fixed literal.

---

## Why SSRF is a distinct concern in agent tools

The mechanism is identical to the OpenAI case; see
[openai_sdk/ssrf.md](../openai_sdk/ssrf.md#why-ssrf-is-a-distinct-concern-in-agent-tools).

The ADK-specific sharpening is **where ADK agents run**. ADK deployments target
Cloud Run, Vertex AI Agent Engine, and GKE — all of which expose the GCP metadata
server at `metadata.google.internal` (`169.254.169.254`). That endpoint vends
OAuth access tokens for the workload's attached **service account** to any local
HTTP caller. Because ADK agents are frequently granted broad GCP roles (to call
Vertex, BigQuery, Storage, etc.), a single model-driven request to
`http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`
yields a token that can act across the project. The `Metadata-Flavor: Google`
header requirement is a trivial obstacle — the tool's own HTTP client can be made
to send it — so it is not a defense.

---

## Rule-by-rule defense

### ADK-009 — Tool fetches a caller-controlled URL (SSRF) (Severity: high, Confidence: 0.6, Fix type: code)

**What we detect:**
A `FunctionTool`-wrapped function whose body makes an HTTP call with a non-literal
URL argument (predicate `has_dynamic_url_call`, an AST walk — comments and
docstrings do not fire).

**Why it is flaggable:**
A non-literal URL means the model picks the destination host, and on GCP the most
valuable destination — the metadata server — is reachable from inside the
runtime.

**Real-world consequence:**
- An ADK `fetch(url: str)` tool on Cloud Run is prompt-injected into requesting
  the metadata token endpoint; the returned service-account token is exfiltrated
  and used to read BigQuery datasets the agent could otherwise only touch through
  its own tools.
- A `call_internal(host: str)` tool is pointed at a VPC-internal admin service
  not exposed to the internet.

**Why severity is high and not medium:**
On a GCP runtime the path from prompt injection to a project-scoped credential is
a single tool call. Not critical only because impact is conditional on the
runtime's network position and the service account's grants, and a host
allow-list plus metadata blocking fully closes it.

**Fix type — code:**
The destination constraint is an edit to the tool's source. A VPC egress policy
blocking the metadata CIDR is complementary defense in depth.

**Confidence 0.6:**
Same profile as OAI-016 — out-of-module validation is invisible to the body-only
walk (false positive), and indirectly-assembled URLs can evade the
first-argument check (false negative).

---

## What this policy does not cover

Identical to [openai_sdk/ssrf.md](../openai_sdk/ssrf.md#what-this-policy-does-not-cover):
out-of-module URL validation, `urllib`/`aiohttp`/raw-socket targets, literal
base + path/userinfo redirect tricks, DNS rebinding and redirect-based SSRF, and
the safety of fetched content. ADK note: the rule does not inspect the
service-account scope, so it cannot tell a low-privilege workload from a
broadly-scoped one — treat any dynamic-URL tool on GCP as high-impact until the
grants are checked.

---

## Recommendations beyond the fix

The safe pattern is the explicit **host** allow-list with post-resolution IP
rejection and disabled redirects from [openai_sdk/ssrf.md](../openai_sdk/ssrf.md#recommendations-beyond-the-fix).
ADK/GCP-specific additions:

1. Block `169.254.169.254` and `metadata.google.internal` at the resolver level
   inside the tool, and at the VPC egress level for the whole workload.
2. Scope the agent's service account to the minimum roles its real tools need, so
   a leaked token's blast radius is small.
3. Prefer IMDS access patterns that are not reachable by an arbitrary in-process
   HTTP call where the platform supports it.
