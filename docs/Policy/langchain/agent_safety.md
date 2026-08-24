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
**Rules:** LC-101, LC-102, LC-103, LC-111
**Severities:** high, low, medium, low
**Fix types:** code, config, code, config
**References:** LLM01 (Prompt Injection), LLM02 (Sensitive Information Disclosure), LLM06 (Excessive Agency), LLM10 (Unbounded Consumption)

---

## What this policy covers

Agent-scope rules for the constructor-shaped LangChain / LangGraph agents Trustabl
discovers: `create_react_agent` and `create_agent` (normalized class `ReactAgent` /
`CreateAgent`) and the legacy `AgentExecutor`. The rules cover the two highest-signal
agent-level risks: wiring a code-execution/shell built-in tool (LC-101), wiring a
raw HTTP `Requests*` built-in whose destination the model chooses (LC-103), and a
tool-calling loop with no explicit iteration cap (LC-102 / LC-111).

The raw `StateGraph` graph agent is a documented discovery gap — its tools and model
are assembled across many call sites, so it is not yet modeled as a single agent.

---

## Rule-by-rule defense

### LC-101 — Agent wires a code-execution or shell built-in tool (Severity: high, Confidence: 0.85, Fix type: code)

**What we detect:** a LangChain agent (`ReactAgent` / `CreateAgent` / `AgentExecutor`)
whose resolved tool set includes `PythonREPLTool`, `PythonAstREPLTool`, or
`ShellTool` (predicate `agent_uses_hosted_tool_class`). Discovery recognizes these
built-ins when they appear in the agent's tool list — including the common
positional form, `create_react_agent(model, [PythonREPLTool()])` — and records them
as hosted-tool edges.

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

### LC-103 — Agent wires a raw HTTP Requests built-in tool (Severity: medium, Confidence: 0.75, Fix type: code)

**What we detect:** a LangChain agent (`ReactAgent` / `CreateAgent` / `AgentExecutor` /
`StateGraph`) whose resolved tool set includes one of `langchain_community`'s raw HTTP
built-ins — `RequestsGetTool`, `RequestsPostTool`, `RequestsPutTool`,
`RequestsPatchTool`, `RequestsDeleteTool` (predicate `agent_uses_hosted_tool_class`).
Discovery records these as hosted-tool edges when the class is instantiated directly
in the agent's tool list. This is the *agent-scope* companion to the tool-scope SSRF
rules: LC-005 / LC-013 observe a hand-rolled `requests.get(url)` inside a tool body,
whereas LC-103 fires on the framework's own arbitrary-URL tool being handed to the
agent. Neither implies the other, and a repo can legitimately trip both.

**Why it is flaggable:** the HTTP method is fixed by the class, but the destination is
not — the model supplies the URL. That is a model-directed outbound HTTP capability
(LLM06, Excessive Agency), and the agent host's network position, not the tool, decides
what it can reach. LangChain gates this family behind `allow_dangerous_requests=True`
precisely because wiring it hands the model an unconstrained fetch.

**Real-world consequence:** a support agent given `RequestsGetTool` to read public
documentation is asked, via text it already retrieved, to fetch
`http://169.254.169.254/latest/meta-data/iam/security-credentials/` — instance
credentials come back inside the model's context (LLM02). The write-method variants
raise the ceiling from read to mutate: `RequestsDeleteTool` pointed at an internal
admin endpoint the host can reach issues a real DELETE. In both cases the response body
returns as conversation text, so a hostile page can attempt a second-order injection
(LLM01). None of this is guaranteed — it depends on what the host can actually reach —
but the wiring is what makes it reachable at all.

**Why severity is medium and not high:** the rule observes a *capability being wired*,
not a demonstrated unguarded request. `allow_dangerous_requests=True` means the author
already opted in knowingly, and the destination may be constrained out of band by a
proxy, an egress policy, or a `TextRequestsWrapper` pinned to one base URL. That is
weaker evidence than LC-005's high, which observes an actual dynamic-URL call flowing
from a tool parameter. Medium also matches how the pack rates the same shape in sibling
SDKs — CREW-107 (0.70), PYD-103 (0.75), VAI-009 (0.70).

**Fix type — code:** the remediation is to replace the generic built-in with a
purpose-built tool that pins its destination, which means writing tool and agent source.
Egress controls help, but removing the unconstrained-fetch capability is a code change.

**Confidence 0.75:** the gap is what a class-name match cannot see in either direction.
*False positives:* an agent whose egress is already proxied or host-allow-listed, a
`TextRequestsWrapper` pinned to a single vetted base URL, or a fixture/dev-only agent —
all still fire. *False negatives:* `RequestsToolkit`, which builds the same tools via
`get_tools()` rather than putting a class in the list; the
`Tool(func=requests_wrapper.get)` wrapper shape; and custom `BaseTool` subclasses that
hand-roll the same capability — none are in the closed class list. It sits above
CREW-107/VAI-009's 0.70 because these five classes have exactly one purpose and the
match is unambiguous, and below LC-101's 0.85 because outbound HTTP has far more
legitimate, adequately-constrained uses than an arbitrary-code REPL.

### LC-111 — TypeScript AgentExecutor has no explicit maxIterations limit (Severity: low, Confidence: 0.6, Fix type: config)

**What we detect:** a TS `AgentExecutor` with no effective `maxIterations` kwarg.

**Why it is flaggable / consequence:** identical to LC-102 in LangChain.js.

**Severity low / Confidence 0.6:** same profile as LC-102.

---

## What this policy does not cover

The raw `StateGraph` agent (discovery gap), v1 `create_agent` middleware quality, and
whether a code-execution tool is *actually* sandboxed out of band. The iteration rules
check `AgentExecutor` only — `create_react_agent` / `create_agent` enforce their own
recursion limit differently and are out of scope here.

LC-103 detects direct wiring of the five known `Requests*` classes and nothing else. It
does not see `RequestsToolkit` (same capability, assembled through `get_tools()`), the
`Tool(func=requests_wrapper.get)` wrapper form, a custom `BaseTool` subclass that
hand-rolls an arbitrary fetch, or any other library's HTTP tool. It also cannot tell
whether an allow-list, an egress proxy, or a pinned base URL is already enforcing the
destination, so a properly constrained deployment still fires.

---

## Recommendations beyond the fix

Remove REPL/shell built-ins from production agents; if code execution is required,
run it in an isolated sandbox and gate it behind a human-in-the-loop approval (a
LangGraph `interrupt_before` breakpoint or a tool-approval middleware). Set
`max_iterations` / `maxIterations` (and a `max_execution_time`) sized to the task,
and set `handle_parsing_errors` so a malformed model step surfaces rather than
retrying forever.

For outbound HTTP, prefer a purpose-built tool that pins the base URL and takes only a
path or query from the model over a generic `Requests*` built-in. Where open fetching is
genuinely required, allow-list the permitted hosts, reject private and link-local ranges,
re-validate the destination after every redirect rather than trusting the first check,
and route the agent's egress through a proxy that refuses internal addresses. Treat every
response body as untrusted input: keep it out of the system prompt and do not let it
widen the agent's tool permissions.
