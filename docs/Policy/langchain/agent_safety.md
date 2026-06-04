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
    severity: medium
    confidence: 0.8
    scope: agent
    fix_type: config
  - id: LC-111
    severity: medium
    confidence: 0.8
    scope: agent
    fix_type: config
references: [LLM06, LLM10]
---

# Policy Rationale: LangChain Agent Safety

**Policy ID:** `langchain_agent_safety`
**File:** `langchain/agent_safety.yaml`
**Rules:** LC-101, LC-102, LC-111
**Severities:** high, medium
**Fix types:** code, config
**References:** LLM06 (Excessive Agency), LLM10 (Unbounded Consumption)

---

## What this policy covers

Agent-scope rules for the constructor-shaped LangChain / LangGraph agents Trustabl
discovers: `create_react_agent` and `create_agent` (normalized class `ReactAgent` /
`CreateAgent`) and the legacy `AgentExecutor`. The rules cover the two highest-signal
agent-level risks: wiring a code-execution/shell built-in tool (LC-101) and an
unbounded tool-calling loop (LC-102 / LC-111).

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

### LC-102 — AgentExecutor has no max_iterations limit (Severity: medium, Confidence: 0.8, Fix type: config)

**What we detect:** an `AgentExecutor` with no effective `max_iterations` kwarg
(predicate `agent_kwarg_missing`).

**Why it is flaggable:** with no iteration ceiling, a model that never emits a final
answer — it loops calling tools, or oscillates between two — runs until it exhausts
the API budget or wall-clock (LLM10, Unbounded Consumption). When the looped tools
have side effects, the runaway loop is also a correctness and safety problem, not
just a cost one.

**Severity medium:** a cost/availability incident rather than a direct compromise.
**Confidence 0.8:** an executor wrapped by an external timeout or a custom loop
guard is over-flagged.

### LC-111 — TypeScript AgentExecutor has no maxIterations limit (Severity: medium, Confidence: 0.8, Fix type: config)

**What we detect:** a TS `AgentExecutor` with no effective `maxIterations` kwarg.

**Why it is flaggable / consequence:** identical to LC-102 in LangChain.js.

**Severity medium / Confidence 0.8:** same profile.

---

## What this policy does not cover

The raw `StateGraph` agent (discovery gap), the `Requests*` SSRF built-ins (recorded
as hosted edges but not yet a dedicated agent rule), v1 `create_agent` middleware
quality, and whether a code-execution tool is *actually* sandboxed out of band. The
iteration rules check `AgentExecutor` only — `create_react_agent` / `create_agent`
enforce their own recursion limit differently and are out of scope here.

---

## Recommendations beyond the fix

Remove REPL/shell built-ins from production agents; if code execution is required,
run it in an isolated sandbox and gate it behind a human-in-the-loop approval (a
LangGraph `interrupt_before` breakpoint or a tool-approval middleware). Set
`max_iterations` / `maxIterations` (and a `max_execution_time`) sized to the task,
and set `handle_parsing_errors` so a malformed model step surfaces rather than
retrying forever.
