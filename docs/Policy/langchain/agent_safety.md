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
  - id: LC-113
    severity: low
    confidence: 0.6
    scope: agent
    fix_type: config
  - id: LC-114
    severity: medium
    confidence: 0.6
    scope: agent
    fix_type: code
references: [LLM06, LLM10]
---

# Policy Rationale: LangChain Agent Safety

**Policy ID:** `langchain_agent_safety`
**File:** `langchain/agent_safety.yaml`
**Rules:** LC-101, LC-102, LC-111, LC-113, LC-114
**Severities:** high, low, low, low, medium
**Fix types:** code, config, config, config, code
**References:** LLM06 (Excessive Agency), LLM10 (Unbounded Consumption)

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

## Why agent safety is a distinct concern in LangChain

An agent's entire capability surface is a list literal handed to a constructor.
`create_react_agent(model, [PythonREPLTool()])` grants arbitrary code execution
in one positional argument, with no keyword naming the risk, no
`allow_dangerous_*` flag to type, and nothing at the call site that reads
differently from wiring a calculator. The security boundary and an ordinary
argument list are the same object, which is why these rules attach to the
**agent** rather than to a tool: the defect is not what any single tool does, it
is what the assembled set adds up to.

That surface is also assembled through several shapes — `create_react_agent`,
`create_agent`, and the legacy `AgentExecutor` — that differ in how they bound a
run. `AgentExecutor` takes `max_iterations`; the graph-based constructors
enforce a recursion limit of their own instead. So "is this agent bounded?" has
no single answer in this ecosystem, and a reviewer who has internalized one
constructor's answer will read the other as safe. LC-102 and LC-111 deliberately
scope to `AgentExecutor` for that reason, and the gap is named below rather than
papered over.

The two risks are also unusually asymmetric for one policy file. LC-101 is a
capability that cannot be tuned — a REPL on the tool surface is either there or
not — while the iteration rules flag a missing *explicit* bound behind a
framework default that already prevents a true runaway. High and low severity
sit together here not by inconsistency but because a code-execution grant and an
unsized loop fail in different orders of magnitude.

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
sandbox-and-gate it. `PythonREPLTool` / `PythonAstREPLTool` run model-generated
Python via an in-process `exec()`/eval in the agent's own interpreter, and
`ShellTool` hands the model a host subprocess shell — no container, no allowlist,
no approval gate anywhere in the tool itself. It is kept off critical for the same
calibration reason as CREW-102 (CrewAI's `unsafe` host execution, also high): the
engine reserves that tier, and the rule still requires that the agent actually be
driven to the tool by model-influenced input — an agent exercised only on trusted,
non-injectable input never reaches it. **Confidence 0.85:** a few agents legitimately
need a REPL and have sandboxed it out of band, which the class-name match cannot
see.

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

### LC-113 — AgentExecutor has no explicit max_execution_time limit (Severity: low, Confidence: 0.6, Fix type: config)

**What we detect:**
A Python `AgentExecutor` with no effective `max_execution_time` kwarg (absent or an
explicit `None`; predicate `agent_kwarg_missing`). It is the wall-clock companion to
LC-102 and reads the same constructor.

**Why it is flaggable:**
`max_iterations` (LC-102) counts tool round-trips, not seconds. One iteration that
blocks on a slow tool or a stalled model call is not counted, so the run can hang or
stretch well past any latency budget while holding tools and credentials live
(LLM10, Unbounded Consumption). `max_execution_time` is the executor's native
wall-clock cap.

**Real-world consequence:**
A support agent's lookup tool waits on an unresponsive internal API; the executor
sits inside iteration 2 of 15 for minutes, the request thread is pinned, and the
front end times out while the agent keeps running.

**Why severity is low and not medium:**
The impact is latency, availability and cost, bounded by external supervision; the
rule grants nothing new to the model and is a hygiene nudge that mirrors LC-102's
low.

**Fix type — config:**
One constructor kwarg, no tool source changes.

**Confidence 0.6:**
**False positives:** an executor wrapped by an external timeout, or whose tools each
carry a timeout that already bounds every step, is over-flagged, as is
`AgentExecutor(**cfg)` (the predicate does not consult the opaque flag). **False
negatives:** the check is presence-only, so an enormous value passes.
`create_react_agent` / `create_agent` graphs are out of scope because they are
bounded by the graph's recursion limit rather than this kwarg. The TypeScript
`AgentExecutor` is deliberately not covered: no `maxExecutionTime` option could be
verified for LangChain.js, and the rule will not advise an option that may not exist.
### LC-114 — LangGraph StateGraph is compiled with no checkpointer (Severity: medium, Confidence: 0.6, Fix type: code)

**What we detect:** a `StateGraph(...)` / `MessageGraph(...)` builder whose
`.compile(...)` call discovery resolved through a named builder variable
(`agent_kwargs_observed: true`), that sets no `checkpointer` (`agent_kwarg_missing`,
which also treats an explicit `checkpointer=None` as missing), in a repo that ships
no `langgraph.json` (`repo_langgraph_platform_config_present: false`). A bare
`builder.compile()` counts as resolved-and-empty; a chained
`StateGraph(...).compile()`, a `compile(**cfg)`, and a graph whose compiled result is
passed to another builder's `add_node` (a subgraph) are all treated as *unobserved*
and stay silent.

**Why it is flaggable:** a checkpointer is what persists graph state between steps.
Without one the run lives only in process memory: a crash, restart or deploy
discards completed steps and tool results, a retry re-executes side-effecting nodes
from the start, and `interrupt()` / `interrupt_before` cannot resume because there
is no saved state to resume from — so a graph that appears to have a human-approval
gate cannot actually pause for one.

**Real-world consequence:** a graph that sends an email in node 3 crashes in node 5;
the supervisor restarts the worker and the run replays from node 1, sending the
email twice. Or an `interrupt()` approval gate raises at runtime because the graph
was compiled without a checkpointer, and the team "fixes" it by deleting the gate.

**Why severity is medium and not high:** the failure needs a crash, restart or
interrupt to bite, and many short-lived graphs legitimately never need to resume.
It is a durability and approval-gate prerequisite rather than a direct exposure.
**Fix type — code:** the checkpointer is passed in the `.compile(...)` call.

**Confidence 0.6:** the gap covers (a) a subgraph compiled in another file, which
inherits its parent's checkpointer and is intentionally compiled bare; (b) a
Platform deployment whose `langgraph.json` lives outside the scanned tree;
(c) a checkpointer attached by a wrapper that returns the compiled graph. The
`agent_kwargs_observed` and `langgraph.json` clauses exist precisely to cut the two
largest false-positive classes: unresolved call sites and Platform repos.

---

## What this policy does not cover

The raw `StateGraph` agent (discovery gap), the `Requests*` SSRF built-ins (recorded
as hosted edges but not yet a dedicated agent rule), v1 `create_agent` middleware
quality, and whether a code-execution tool is *actually* sandboxed out of band. The
iteration rules check `AgentExecutor` only — `create_react_agent` / `create_agent`
enforce their own recursion limit differently and are out of scope here.
- For LC-113: wall-clock limits enforced outside the executor, and the TypeScript
  `AgentExecutor` (no verified equivalent option, so no rule ships).
- For LC-114: a graph whose `compile(...)` is chained onto the constructor, built
  with `**` unpacking, or compiled in a different file than its builder is never
  linked to its kwargs, so the rule stays silent rather than guess. A subgraph
  compiled in another file than the parent that mounts it cannot be recognised as a
  subgraph and may be flagged. A `checkpointer=` pointing at a throwaway
  `MemorySaver()` in production satisfies the rule without giving real durability.

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
