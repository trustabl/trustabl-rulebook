---
policy_id: langchain_agent_safety
category: langchain
topic: agent_safety
rules:
  - id: LC-101
    severity: high
    confidence: 0.85
    scope: agent
    fix_type: code
  - id: LC-102
    severity: low
    confidence: 0.6
    scope: agent
    fix_type: config
  - id: LC-103
    severity: medium
    confidence: 0.7
    scope: agent
    fix_type: code
  - id: LC-104
    severity: high
    confidence: 0.75
    scope: agent
    fix_type: code
  - id: LC-111
    severity: low
    confidence: 0.6
    scope: agent
    fix_type: config
references: [LLM01, LLM02, LLM06, LLM10]
---

# Policy Rationale: LangChain Agent Safety

**Policy ID:** `langchain_agent_safety`
**File:** `langchain/agent_safety.yaml`
**Rules:** LC-101, LC-102, LC-103, LC-104, LC-111
**Severities:** high, low, medium, high, low
**Fix types:** code, config, code, code, config
**References:** LLM01 (Prompt Injection), LLM02 (Sensitive Information Disclosure), LLM06 (Excessive Agency), LLM10 (Unbounded Consumption)

---

## What this policy covers

Agent-scope rules for the constructor-shaped LangChain / LangGraph agents Trustabl
discovers: `create_react_agent` and `create_agent` (normalized class `ReactAgent` /
`CreateAgent`) and the legacy `AgentExecutor`. The rules cover three agent-level
risks: wiring a code-execution/shell built-in tool (LC-101), wiring a raw HTTP
built-in whose destination the model chooses (LC-103 read-only, LC-104
state-changing), and a tool-calling loop with no explicit iteration cap
(LC-102 / LC-111).

All three capability rules read the same discovery signal. Trustabl recognizes a
fixed set of high-risk LangChain built-in classes when they appear in an agent's
tool list and records each as a hosted-tool edge, which
`agent_uses_hosted_tool_class` then matches. The set is deliberately narrow —
benign built-ins are omitted, so a match is always a meaningful capability grant
rather than an inventory note.

---

## Rule-by-rule defense

### LC-101 — Agent wires a code-execution or shell built-in tool (Severity: high, Confidence: 0.85, Fix type: code)

**What we detect:** a LangChain agent (`ReactAgent` / `CreateAgent` / `AgentExecutor`)
whose resolved tool set includes `PythonREPLTool`, `PythonAstREPLTool`, the bare
`PythonREPL` utility, or `ShellTool` (predicate `agent_uses_hosted_tool_class`).
Discovery recognizes these built-ins when they appear in the agent's tool list —
including the common positional form, `create_react_agent(model, [PythonREPLTool()])`
— and records them as hosted-tool edges.

`PythonREPL` is the raw `langchain_experimental` utility that `PythonREPLTool` wraps;
`tools=[PythonREPL()]` grants the same arbitrary-execution capability with one less
layer. It is in the engine's code-execution class set, so it was already discovered
as a hosted edge, but the rule did not list it — an RCE-class wiring that scanned
clean. It is now covered.

**Why it is flaggable:** these built-ins execute code or shell commands chosen by
the model. Once one is on the tool surface, a prompt injection or a confused model
has a direct path to arbitrary execution in the agent process. PythonREPLTool and
ShellTool have been the concrete vector in multiple published LangChain RCE
advisories — this is excessive agency (LLM06) in its most literal form: the agent is
granted the ability to run anything.

**Real-world consequence:** an agent built to "answer questions about a CSV" is
given a `PythonREPLTool`; a crafted question makes it run `__import__('os').system(...)`
and read the deployment's secrets.

**Severity high:** the capability is the defect; the fix is to remove the built-in or
sandbox-and-gate it. **Confidence 0.85:** a few agents legitimately need a REPL and
have sandboxed it out of band, which the class-name match cannot see.

### LC-102 — AgentExecutor has no explicit max_iterations limit (Severity: low, Confidence: 0.6, Fix type: config)

**What we detect:** an `AgentExecutor` with no effective `max_iterations` kwarg
(predicate `agent_kwarg_missing`).

**Why it is flaggable:** with no explicit `max_iterations`, the executor falls back
to LangChain's default of 15 — a generic ceiling, not one sized to this task. A
model that loops or oscillates still runs up to 15 tool round-trips (LLM10,
Unbounded Consumption), a cost the workflow may not tolerate, and the implicit cap
can shift between versions; when the looped tools have side effects it is a
correctness concern too.

**Severity low:** the framework default (15) already prevents a true runaway, so
this flags a missing *explicit, task-sized* cap — a hygiene nudge, not a defect.
**Confidence 0.6:** an executor relying on the default, wrapped by an external
timeout, or guarded by a custom loop is over-flagged.

### LC-103 — Agent wires a read-only raw HTTP built-in tool (Severity: medium, Confidence: 0.7, Fix type: code)

**What we detect:** a LangChain agent whose resolved tool set includes
`RequestsGetTool` (predicate `agent_uses_hosted_tool_class`). This is the
`langchain_community` wrapper that issues an outbound GET to whatever URL the model
puts in the tool call.

**Why it is flaggable:** the destination is an argument, not a configured endpoint.
A tool that fetches an allow-listed API is a bounded capability; a tool that fetches
*any* URL the model names is server-side request forgery with the model as the
confused deputy. The agent's network position is the whole attack surface — cloud
metadata endpoints and internal admin services routinely authorize callers by source
address alone, so "the agent can reach it" is equivalent to "the model can read it"
(LLM02, Sensitive Information Disclosure). The response body then re-enters the
conversation as untrusted text, giving the fetched host a second-order
prompt-injection channel (LLM01). LangChain classifies these tools as dangerous in
its own API: `BaseRequestsTool` refuses to construct unless the caller passes
`allow_dangerous_requests=True`.

**Real-world consequence:** an agent given `RequestsGetTool` to "look up public
documentation" is asked, via an injected instruction in a retrieved page, to fetch
`http://169.254.169.254/latest/meta-data/iam/security-credentials/`. The
role credentials come back in the tool result and are then available to the model
for the rest of the session.

**Why severity is medium and not high:** the capability reads; it does not write. The
exposure is real but recoverable — no remote state changes, and an operator who
rotates the leaked credential has undone the damage. That is the same line drawn for
CrewAI's model-chosen-URL built-ins in
[crewai/dangerous_tools.md](../crewai/dangerous_tools.md), which sit at medium for
the identical shape. LC-104 covers the write verbs, where that recovery argument does
not hold.

**Fix type — code:** the durable fix is to replace the generic fetcher with a tool
that pins the host and path template and accepts only query parameters, which is new
tool source rather than an agent-constructor change.

**Confidence 0.7:** the class-name match cannot see out-of-band mitigation. An agent
may legitimately wire the tool behind an egress proxy, a network policy that blocks
link-local and RFC 1918 ranges, or a LangGraph approval interrupt — all of which
leave the wiring intact and the finding standing. The corresponding false negative is
a hand-written tool that takes a `url` parameter and calls `requests.get` directly:
that shape is not a recognized built-in class, so it is LC-005's job at tool scope,
not this rule's.

### LC-104 — Agent wires a state-changing raw HTTP built-in tool (Severity: high, Confidence: 0.75, Fix type: code)

**What we detect:** a LangChain agent whose resolved tool set includes
`RequestsPostTool`, `RequestsPutTool`, `RequestsPatchTool`, or `RequestsDeleteTool`
(predicate `agent_uses_hosted_tool_class`).

**Why it is flaggable:** both the destination and the request body are model-supplied.
This is strictly more than the LC-103 exposure: the model is not limited to reading
data it should not reach, it can create, overwrite, or delete state on any host the
agent can route to. Internal APIs that trust callers by network position are the
worst case, because they typically expose destructive operations without a second
authorization check. Two properties make it harder to contain than a read. The effect
is not undone by discarding the response, so a guardrail that inspects tool *output*
is already too late. And LangChain's own retry and loop behaviour can re-issue the
call, so a single injected instruction can apply the write more than once. These
tools are also gated behind `allow_dangerous_requests=True` in LangChain's API.

**Real-world consequence:** an agent wired with `RequestsDeleteTool` to "clean up
stale records through our API" processes a document containing an injected
instruction and issues `DELETE` against an internal service's collection endpoint.
The records are gone before any output-side guardrail sees the tool result.

**Why severity is high and not medium:** the capability is irreversible and
unbounded in destination. Unlike LC-103 there is no post-hoc remediation equivalent
to rotating a credential — the write has landed. This matches the high assigned to
CrewAI's model-driven file-writing built-in (CREW-109) on the same reasoning: a
model-chosen mutation is a defect in the tool surface, not a hygiene gap.

**Fix type — code:** the fix is to expose each legitimate mutation as its own tool
with a pinned method, host, and path, a schema-validated payload, and an idempotency
key — all tool source.

**Confidence 0.75:** marginally above LC-103. The write verbs carry no benign reading
of the capability, so the "this is probably fine" false positive is rarer; a team
wiring `RequestsDeleteTool` has granted model-driven deletion whatever else is in
place. The residual gap is the same out-of-band mitigation LC-103 has — an egress
allow-list or a human-in-the-loop interrupt the class-name match cannot observe.

### LC-111 — TypeScript AgentExecutor has no explicit maxIterations limit (Severity: low, Confidence: 0.6, Fix type: config)

**What we detect:** a TS `AgentExecutor` with no effective `maxIterations` kwarg.

**Why it is flaggable / consequence:** identical to LC-102 in LangChain.js.

**Severity low / Confidence 0.6:** same profile as LC-102.

---

## What this policy does not cover

- **Hand-written equivalents.** All three capability rules match a fixed list of
  built-in *class names*. A tool that takes a `url` argument and calls
  `requests.get` itself, or shells out to `curl`, grants the same capability and is
  invisible here — that is the tool-scope pack's job (LC-003 shell, LC-005 SSRF).
- **Out-of-band mitigation.** An egress proxy, a network policy blocking link-local
  and RFC 1918 destinations, a sandboxed REPL, or a LangGraph `interrupt_before`
  approval all leave the wiring intact, so the finding stands even when the risk is
  already controlled. This is the dominant false positive for LC-101/103/104.
- **Indirect wiring.** The `Tool(func=PythonREPL().run)` shape wraps a *method*
  rather than placing the class in `tools=[...]`, so it is not recorded as a hosted
  edge and does not fire. Tool lists bound to a variable and assembled elsewhere are
  a known discovery gap for the same reason.
- **The remaining `Requests*` surface.** `RequestsGetTool` and the four write verbs
  are covered; the `TextRequestsWrapper` utility and the OpenAPI/Toolkit shapes that
  bundle them are not yet recognized as classes.
- **Whether the capability is warranted.** These rules report that a capability was
  granted, not that it was granted wrongly. An agent that genuinely needs a fetcher
  will fire LC-103 forever; suppress it deliberately rather than treating the finding
  as a bug.
- **Scope limits.** The raw `StateGraph` agent's tool list is assembled across call
  sites (discovery gap), v1 `create_agent` middleware quality is unmodeled, and the
  iteration rules check `AgentExecutor` only — `create_react_agent` / `create_agent`
  enforce their own recursion limit differently.

---

## Recommendations beyond the fix

The safe replacement for a generic fetcher is a tool that owns the destination and
lets the model choose only the arguments:

```python
from urllib.parse import quote

import requests
from langchain_core.tools import tool

ALLOWED_HOST = "https://api.example.com"


@tool
def lookup_invoice(invoice_id: str) -> dict:
    """Look up one invoice by its ID."""
    if not invoice_id.isalnum():
        raise ValueError("invoice_id must be alphanumeric")
    resp = requests.get(
        f"{ALLOWED_HOST}/invoices/{quote(invoice_id)}",
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()
```

The model still drives the lookup, but it cannot name the host, the path, or the
method, so there is no SSRF surface to injection-proof.

1. **Remove REPL/shell built-ins from production agents.** If code execution is
   genuinely required, run it in an isolated sandbox (no network, no credentials,
   read-only filesystem, hard timeout) and gate it behind a human-in-the-loop
   approval — a LangGraph `interrupt_before` breakpoint or a tool-approval
   middleware.
2. **Block link-local and private address space at the egress layer**, not in the
   tool. Resolve the hostname and reject `169.254.0.0/16`, loopback, and RFC 1918
   *after* resolution, so a DNS name that resolves into private space is caught too.
3. **Treat every tool result as untrusted input.** A fetched page is data, never
   instructions; keep it out of the system prompt and do not let it widen the tool
   surface.
4. **Give write-capable tools an idempotency key** and log every call with the
   session ID, so a retried or replayed mutation is detectable and non-duplicating.
5. **Set `max_iterations` / `maxIterations`** (and a `max_execution_time`) sized to
   the task, and set `handle_parsing_errors` so a malformed model step surfaces
   rather than retrying forever.
