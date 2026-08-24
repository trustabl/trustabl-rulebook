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
  - id: LC-111
    severity: low
    confidence: 0.6
    scope: agent
    fix_type: config
  - id: LC-112
    severity: high
    confidence: 0.7
    scope: agent
    fix_type: config
references: [LLM06, LLM10]
---

# Policy Rationale: LangChain Agent Safety

**Policy ID:** `langchain_agent_safety`
**File:** `langchain/agent_safety.yaml`
**Rules:** LC-101, LC-102, LC-111, LC-112
**Severities:** high, low, low, high
**Fix types:** code, config, config, config
**References:** LLM06 (Excessive Agency), LLM10 (Unbounded Consumption)

---

## What this policy covers

Agent-scope rules for the constructor-shaped LangChain / LangGraph agents Trustabl
discovers: `create_react_agent` and `create_agent` (normalized class `ReactAgent` /
`CreateAgent`) and the legacy `AgentExecutor`. The rules cover the two highest-signal
agent-level risks: wiring a code-execution/shell built-in tool (LC-101) and a
tool-calling loop with no explicit iteration cap (LC-102 / LC-111). LC-112 adds a
narrow check that a privileged LangChain v1 `create_agent` has the constructor-level
prerequisites for a resumable human-approval boundary: non-empty `middleware` and an
effective `checkpointer`.

The raw `StateGraph` graph agent is a documented discovery gap — its tools and model
are assembled across many call sites, so it is not yet modeled as a single agent.

---

## Why approval boundaries are a distinct concern in agent tools

A conventional application usually reaches a shell or interpreter through a code
path written directly by a developer. An agent can instead select that capability
from model output. Prompt injection, ambiguous instructions, or model error can
therefore become an execution request without a new human-authored code path.

For high-impact tools, a human approval gate creates an authorization boundary
between model intent and external effect. A resumable LangChain v1 approval flow
needs middleware to introduce the interrupt and checkpoint state so execution can
resume after the decision. If a privileged `create_agent` lacks either prerequisite,
Trustabl can establish that this interrupt/resume structure is absent from the
constructor it can statically inspect.

LC-112 deliberately does not claim that the human review is effective. Static
analysis cannot determine whether a reviewer sees the exact command, understands
its consequence, or rubber-stamps it. The rule verifies a machine-checkable
prerequisite for review rather than reviewer cognition.

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

### LC-111 — TypeScript AgentExecutor has no explicit maxIterations limit (Severity: low, Confidence: 0.6, Fix type: config)

**What we detect:** a TS `AgentExecutor` with no effective `maxIterations` kwarg.

**Why it is flaggable / consequence:** identical to LC-102 in LangChain.js.

**Severity low / Confidence 0.6:** same profile as LC-102.

### LC-112 — LangChain privileged create_agent lacks human-approval prerequisites (Severity: high, Confidence: 0.7, Fix type: config)

**What we detect:** a Python LangChain `CreateAgent` that wires
`PythonREPLTool`, `PythonAstREPLTool`, or `ShellTool` and either has no/empty
`middleware` kwarg or has no effective `checkpointer` kwarg. The rule composes the
existing `agent_class`, `agent_uses_hosted_tool_class`, `agent_kwarg_list_empty`, and
`agent_kwarg_missing` predicates.

**Why it is flaggable:** the model has a direct path to a high-impact execution
capability while the constructor lacks one or both structural prerequisites for an
interrupt/resume approval flow. Without that boundary, model-selected tool input can
reach the privileged capability in the same autonomous run.

**Real-world consequence:** an agent used for repository maintenance exposes
`ShellTool`. Prompt-injected issue text steers the model toward a destructive shell
command. Without approval middleware and checkpointing, there is no constructor-level
pause/resume boundary Trustabl can verify before execution.

**Why severity is high and not critical:** shell/Python execution is high impact, but
the realized consequence still depends on the model selecting a harmful action and
the privileges of the runtime. Sandboxing or external controls may constrain impact.

**Fix type — config:** add human-approval middleware for the privileged tool and a
checkpointer; the underlying tool implementation does not need to change.

**Confidence 0.7:** the rule verifies structural prerequisites, not middleware
semantics. Unrelated non-empty middleware plus a checkpointer can silence LC-112,
while an out-of-band approval system invisible to `create_agent` kwargs can make a
finding safer than it appears.

---

## What this policy does not cover

The raw `StateGraph` agent (discovery gap), the `Requests*` SSRF built-ins (recorded
as hosted edges but not yet a dedicated agent rule), whether a code-execution tool
is *actually* sandboxed out of band, or whether LC-112's non-empty middleware is
specifically `HumanInTheLoopMiddleware` and gates every privileged tool. The
iteration rules check `AgentExecutor` only — `create_react_agent` / `create_agent`
enforce their own recursion limit differently and are out of scope there. LC-112
also cannot determine whether a human sees raw action arguments, understands them,
or rubber-stamps a model-written summary.

---

## Recommendations beyond the fix

Remove REPL/shell built-ins from production agents; if code execution is required,
run it in an isolated sandbox and gate it behind a human-in-the-loop approval. For
LangChain v1 `create_agent`, a safe constructor shape is:

```python
from langchain.agents import create_agent
from langchain.agents.middleware import HumanInTheLoopMiddleware
from langchain_experimental.tools import ShellTool
from langgraph.checkpoint.memory import InMemorySaver

agent = create_agent(
    model="openai:gpt-5",
    tools=[ShellTool()],
    middleware=[
        HumanInTheLoopMiddleware(
            interrupt_on={"shell": True},
            description_prefix="Review the exact shell action before execution",
        )
    ],
    checkpointer=InMemorySaver(),
)
```

Present the reviewer with the exact tool name and arguments, bind approval to that
specific proposed action, and require a new approval if the action changes. Set
`max_iterations` / `maxIterations` (and a `max_execution_time`) sized to the task,
and set `handle_parsing_errors` so a malformed model step surfaces rather than
retrying forever.
