---
policy_id: langchain_agent_safety
category: langchain
topic: agent_safety
rules:
  - id: LC-101
    severity: critical
    confidence: 0.85
    scope: agent
    fix_type: code
  - id: LC-102
    severity: low
    confidence: 0.6
    scope: agent
    fix_type: config
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
references: [LLM06, LLM10]
---

# Policy Rationale: LangChain Agent Safety

**Policy ID:** `langchain_agent_safety`
**File:** `langchain/agent_safety.yaml`
**Rules:** LC-101, LC-102, LC-111, LC-113
**Severities:** critical, low, low, low
**Fix types:** code, config, config, config
**References:** LLM06 (Excessive Agency), LLM10 (Unbounded Consumption)

---

## What this policy covers

Agent-scope rules for the constructor-shaped LangChain / LangGraph agents Trustabl
discovers: `create_react_agent` and `create_agent` (normalized class `ReactAgent` /
`CreateAgent`) and the legacy `AgentExecutor`. The rules cover the two highest-signal
agent-level risks: wiring a code-execution/shell built-in tool (LC-101) and a
tool-calling loop with no explicit iteration cap (LC-102 / LC-111).

The raw `StateGraph` graph agent is a documented discovery gap — its tools and model
are assembled across many call sites, so it is not yet modeled as a single agent.

---

## Rule-by-rule defense

### LC-101 — Agent wires a code-execution or shell built-in tool (Severity: critical, Confidence: 0.85, Fix type: code)

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

**Severity critical:** the engine reserves critical for unconditional execution, and
these built-ins are exactly that tier. `PythonREPLTool` / `PythonAstREPLTool` run
model-generated Python via an in-process `exec()`/eval in the agent's own
interpreter, and `ShellTool` hands the model a host subprocess shell — no container,
no allowlist, no approval gate anywhere in the tool itself. There is no partial
mitigation for the finding to credit: unlike CrewAI's `allow_code_execution`
(CREW-101, high), where model code still lands inside a Docker sandbox in the
default `safe` mode and an attack must additionally escape it, LangChain ships
these classes with no boundary at all — wiring the tool *is* granting execution
with the agent process's credentials, filesystem, and network. A single injected
instruction closes the gap between text and host compromise in one tool call,
which is why the fix is removal or an out-of-band sandbox-and-gate, not a safer
configuration of the same tool. **Confidence 0.85:** a few agents legitimately
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

---

## What this policy does not cover

The raw `StateGraph` agent (discovery gap), the `Requests*` SSRF built-ins (recorded
as hosted edges but not yet a dedicated agent rule), v1 `create_agent` middleware
quality, and whether a code-execution tool is *actually* sandboxed out of band. The
iteration rules check `AgentExecutor` only — `create_react_agent` / `create_agent`
enforce their own recursion limit differently and are out of scope here.
- For LC-113: wall-clock limits enforced outside the executor, and the TypeScript
  `AgentExecutor` (no verified equivalent option, so no rule ships).

---

## Recommendations beyond the fix

Remove REPL/shell built-ins from production agents; if code execution is required,
run it in an isolated sandbox and gate it behind a human-in-the-loop approval (a
LangGraph `interrupt_before` breakpoint or a tool-approval middleware). Set
`max_iterations` / `maxIterations` (and a `max_execution_time`) sized to the task,
and set `handle_parsing_errors` so a malformed model step surfaces rather than
retrying forever.
