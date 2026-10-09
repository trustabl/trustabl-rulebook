---
policy_id: google_adk_ssrf
category: google_adk
topic: ssrf
rules:
  - id: ADK-012
    severity: high
    confidence: 0.6
    scope: tool
    fix_type: code
  - id: ADK-016
    severity: high
    confidence: 0.6
    scope: tool
    fix_type: code
  - id: ADK-022
    severity: medium
    confidence: 0.6
    scope: tool
    fix_type: code
  - id: ADK-023
    severity: medium
    confidence: 0.6
    scope: tool
    fix_type: code
references: [LLM06, LLM02, LLM01]
---

# Policy Rationale: Server-Side Request Forgery

**Policy ID:** `google_adk_ssrf`  
**File:** `google_adk/ssrf.yaml`  
**Rules:** ADK-012, ADK-016, ADK-022, ADK-023  
**Severities:** high, high, medium, medium  
**Fix types:** code, code, code, code  
**References:** LLM06, LLM02, LLM01

> **Read [claude_sdk/ssrf.md](../claude_sdk/ssrf.md) for the full threat model.**
> This document covers Google ADK–specific differences only.

---

## What this policy covers

Google ADK `FunctionTool`-wrapped functions whose body issues an HTTP request to
a non-literal destination URL. Detection is the same `has_dynamic_url_call` AST
predicate described in the Claude doc — it fires when the URL argument of a
`requests` / `httpx` call (including resolved session aliases) is a parameter, an
interpolated f-string, or a built-up expression rather than a fixed literal.

---

## Why SSRF is a distinct concern in agent tools

The mechanism is identical to the Claude case; see
[claude_sdk/ssrf.md](../claude_sdk/ssrf.md#why-ssrf-is-a-distinct-concern-in-agent-tools).

The ADK-specific sharpening is **where ADK agents run**. ADK deployments target
Cloud Run, Vertex AI Agent Engine, and GKE — all of which expose the GCP metadata
server at `metadata.google.internal` (`169.254.169.254`). That endpoint vends
OAuth access tokens for the workload's attached **service account** to any local
HTTP caller. Because ADK agents are frequently granted broad GCP roles, a single
model-driven request to the metadata token endpoint yields a token that can act
across the project. The `Metadata-Flavor: Google` header requirement is a trivial
obstacle the tool's own client can satisfy, so it is not a defense.

---

## Rule-by-rule defense

### ADK-012 — Tool fetches a caller-controlled URL (SSRF) (Severity: high, Confidence: 0.6, Fix type: code)

**What we detect:**
A `FunctionTool`-wrapped function whose body makes an HTTP call with a non-literal
URL argument (`has_dynamic_url_call`).

**Why it is flaggable:**
A non-literal URL means the model picks the destination host, and on GCP the most
valuable destination — the metadata server — is reachable from inside the runtime.

**Real-world consequence:**
An ADK `fetch(url)` tool on Cloud Run is prompt-injected into requesting the
metadata token endpoint; the returned service-account token is exfiltrated and
used to read BigQuery or Storage the agent could otherwise only touch through its
own tools.

**Why severity is high and not medium:**
On a GCP runtime the path from prompt injection to a project-scoped credential is
a single tool call. Not critical only because impact is conditional on the
runtime's network position and the service account's grants; a host allow-list
plus metadata blocking fully closes it.

**Fix type — code:**
The destination constraint is an edit to the tool's source. A VPC egress policy
blocking the metadata CIDR is complementary defense in depth.

**Confidence 0.6:**
Same profile as the Claude rule — out-of-module validation is invisible to the
body-only walk (false positive), and indirectly-assembled URLs can evade the
first-argument check (false negative).

### ADK-016 — TypeScript FunctionTool fetches a caller-controlled URL (SSRF) (Severity: high, Confidence: 0.6, Fix type: code)

**What we detect:**
A TypeScript `FunctionTool` whose `execute` handler issues an HTTP request with a
non-literal URL argument (`has_dynamic_url_call: true`). The fact is structural:
`tsHandlerFacts` walks the handler, recognizes a `call_expression` whose callee is
one of the `fetch` / `axios(.get/.post/...)` / `got(.get/.post)` / `undici.fetch` /
`undici.request` clients, and inspects that call's first positional argument. A
plain `string`-node literal does **not** fire; a template string with at least one
`${...}` substitution, an identifier, a member expression, or a concatenation does;
a backtick template with no substitution is treated as a literal and does not fire.
Same predicate as the Python sibling
[ADK-012](#adk-012--tool-fetches-a-caller-controlled-url-ssrf-severity-high-confidence-06-fix-type-code),
resolved against the TypeScript HTTP-client shapes.

**Why it is flaggable:**
A non-literal URL means the model picks the destination host, and on a GCP runtime
the most valuable destination — the metadata server at `metadata.google.internal`
(`169.254.169.254`) — is reachable from inside the runtime and vends a
service-account token to any local HTTP caller.

**Real-world consequence:**
A TS `fetch(url)` tool on Cloud Run is prompt-injected into requesting the metadata
token endpoint; the returned service-account token is exfiltrated and used to read
BigQuery or Storage the agent could otherwise only touch through its own tools. The
`Metadata-Flavor: Google` header the endpoint requires is trivially satisfied by the
tool's own client, so it is not a defense.

**Why severity is high and not medium:**
On a GCP runtime the path from prompt injection to a project-scoped credential is a
single tool call — identical to the Python ADK-012. Not critical only because impact
is conditional on the runtime's network position and the service account's grants; a
host allow-list plus metadata blocking fully closes it.

**Fix type — code:**
Constraining the destination (host allow-list, or fixed base URL accepting only a
path/query segment, with post-resolution rejection of private/loopback/link-local
ranges) is an edit to the tool's source. A VPC egress policy blocking the metadata
CIDR is complementary defense in depth.

**Confidence 0.6:**
Matches the Python ADK-012's 0.6. The structural first-argument check correctly
excludes a literal URL by construction, but two error modes keep it here. **False
positives:** a non-literal URL that is in fact validated or constant — an ID checked against an allow-list in another module, or under a name outside the Allow-list credit set, or a base read from config — still fires, because the body-only walk does not see the validation and does not reason about
constancy; the rule also cannot weight impact by the service account's actual scope,
so it treats every dynamic-URL tool on GCP as high-impact. **False negatives:** an
HTTP client outside the recognized `fetch`/`axios`/`got`/`undici` set
(`node:http`/`https` `request`, `superagent`, `ky`, a wrapped client), a URL passed
positionally into a helper that performs the fetch, a `new URL(base, modelValue)`
constructed before the call, and literal-base-plus-path/userinfo redirect tricks all
escape the first-argument check on a known callee.

### ADK-022 — ADK tool fetches an allow-listed host without pinning https:// (Severity: medium, Confidence: 0.6, Fix type: code)

**What we detect:** a Python tool whose body checks the destination host against a named allow-list (the same `has_body_text` credit that silences ADK-012) and makes a recognized HTTP call (`requests`/`httpx`/`urllib`/aliased clients) with a dynamic URL that neither starts with a literal `https://` prefix nor is guarded by a scheme check (`.scheme ==`/`!=`/`in`/`not in`, `startswith("https://")`). Backed by `has_unpinned_scheme_url_call`, which treats an f-string, `+` concatenation, `%`-format, or `.format()` call whose leftmost literal starts with `https://` as pinned.

**Why it is flaggable:** the allow-list (ADK-012's credit) constrains *where* the request goes, not *how*. An `http://` URL for an allowed
host passes the host check, so request headers (API keys, bearer tokens) and bodies travel in cleartext, and a network-path attacker can read
them or rewrite the response. The response re-enters the model's context as trusted tool output, which makes tampering a prompt-injection channel.
A redirect from the allowed host to `http://` has the same effect.

**Real-world consequence:** credential and data disclosure to anyone on the network path (shared Wi-Fi, compromised proxy, hostile egress hop)
and integrity loss of the content the model reasons over.

**Why medium / 0.6:** medium rather than ADK-012's high because the host is already bounded, so the residual risk needs a network-path attacker
rather than just a prompt injection. Confidence is 0.6 because the scheme may be enforced where this rule cannot see it: a helper defined in
another function or module, a base URL configured on a client object, or a prefix built on an earlier line and passed by identifier.

**Staging:** the rule requires the allow-list credit to be present, so ADK-012 and ADK-022 never fire on the same tool: SSRF first, then HTTPS once a host
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

### ADK-023 — TypeScript ADK tool fetches an allow-listed host without pinning https:// (Severity: medium, Confidence: 0.6, Fix type: code)

**What we detect:** a TypeScript tool whose body checks `.hostname`/`.host` against an allow-list (the positive form of the credit that silences ADK-016) and calls `fetch`/`axios`/`got`/`undici` with a dynamic URL that neither starts with a literal `https://` prefix nor is guarded by a `.protocol` comparison or `startsWith("https:")`. Backed by the `url_scheme_unpinned` handler fact computed beside `dynamic_url`; a template string or `+` concatenation whose leftmost fragment is a literal `https://` is treated as pinned.

**Why it is flaggable:** the allow-list (ADK-016's credit) constrains *where* the request goes, not *how*. An `http://` URL for an allowed
host passes the host check, so request headers (API keys, bearer tokens) and bodies travel in cleartext, and a network-path attacker can read
them or rewrite the response. The response re-enters the model's context as trusted tool output, which makes tampering a prompt-injection channel.
A redirect from the allowed host to `http://` has the same effect.

**Real-world consequence:** credential and data disclosure to anyone on the network path (shared Wi-Fi, compromised proxy, hostile egress hop)
and integrity loss of the content the model reasons over.

**Why medium / 0.6:** medium rather than ADK-016's high because the host is already bounded, so the residual risk needs a network-path attacker
rather than just a prompt injection. Confidence is 0.6 because the scheme may be enforced where this rule cannot see it: a helper defined in
another function or module, a base URL configured on a client object, or a prefix built on an earlier line and passed by identifier.

**Staging:** the rule requires the allow-list credit to be present, so ADK-016 and ADK-023 never fire on the same tool: SSRF first, then HTTPS once a host
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

ADK-012, ADK-016 used to fire on every non-literal destination, including tools that had already constrained the host, which made the rule a false-positive source for exactly the code that followed its own fix advice. The match is now `has_dynamic_url_call` **and not** a recognized host allow-list in the tool body. Severity, confidence and scope are unchanged.

**Python (ADK-012).** The rule is silenced when the function body contains a hostname membership test against a named allow-list: `.hostname not in`, `.netloc not in`, or one of `ALLOWED_HOSTS`, `ALLOWED_DOMAINS`, `allowed_hosts`, `allowed_domains`, `HOST_ALLOWLIST`, `host_allowlist` (predicate `not: has_body_text`). A bare `.hostname in` is deliberately *not* credited, because it cannot tell an allow-list from a deny-list.

**TypeScript (ADK-016).** The rule is silenced when the handler both reads a host (`.hostname` / `.host`) and tests membership (`.includes(` / `.has(`), or references a named allow-list (`allowedHosts`, `allowedDomains`, `ALLOWED_HOSTS`, `ALLOWED_DOMAINS`, `hostAllowlist`). Reading `new URL(x).hostname` with no membership test does not silence it.

The credit is textual and body-local. It does not verify that the allow-list is correct, that the check runs before the request, or that the request cannot be redirected to a host outside it; HTTPS-only enforcement and a redirect cap are recommended in each rule's fix text but are not separately detected.

---

## What this policy does not cover

Identical to [claude_sdk/ssrf.md](../claude_sdk/ssrf.md#what-this-policy-does-not-cover):
out-of-module URL validation, `urllib`/`aiohttp`/raw-socket targets, literal base
+ path/userinfo redirect tricks, DNS rebinding, and the safety of fetched content.
ADK note: the rule does not inspect the service-account scope, so it cannot weight
impact by the agent's GCP grants — treat any dynamic-URL tool on GCP as
high-impact until the grants are checked. For ADK-016 specifically: HTTP clients
outside the recognized `fetch`/`axios`/`got`/`undici` set (`node:http`/`https`
`request`, `superagent`, `ky`, a wrapped client), a URL constructed via
`new URL(base, modelValue)` before the call, and a model-supplied value passed
positionally into a helper that performs the fetch all escape the first-argument
check on a known callee.
- An allow-list enforced in a helper or middleware outside the tool body, an allow-list check that uses a name outside the recognized set, and a membership test that is unrelated to the URL host but happens to sit beside a `.host` read (TypeScript over-credit). Redirects and non-HTTPS schemes are not detected.

---

## Recommendations beyond the fix

The safe pattern — an explicit **host** allow-list with post-resolution IP
rejection and disabled redirects — is in
[claude_sdk/ssrf.md](../claude_sdk/ssrf.md#recommendations-beyond-the-fix).
ADK/GCP-specific additions:

1. Block `169.254.169.254` and `metadata.google.internal` at the resolver level in
   the tool, and at the VPC egress level for the whole workload.
2. Scope the agent's service account to the minimum roles its real tools need, so
   a leaked token's blast radius is small.
3. Gate fetching tools with a `before_tool_callback` that allow-lists hosts before
   the request runs.
