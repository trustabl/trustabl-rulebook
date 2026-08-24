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

Agent-scope rules for constructor-shaped LangChain / LangGraph agents Trustabl discovers: `create_react_agent`, LangChain v1 `create_agent`, and legacy `AgentExecutor`, plus raw `StateGraph` where supported by discovery. The policy covers dangerous code/shell capability, explicit iteration limits, and—via LC-112—the structural prerequisites for pausing a privileged v1 `create_agent` for human approval and then resuming from persisted state.

---

## Why approval boundaries are a distinct concern in agent tools

A conventional application usually reaches a shell, interpreter, or other destructive capability through application code written by a developer. An agent can instead select that capability from model output. Prompt injection, ambiguous instructions, or model error can therefore become an execution request without a new human-authored code path.

For high-impact tools, a human approval gate creates an authorization boundary between model intent and external effect. In LangChain v1, a resumable human-in-the-loop flow needs middleware to introduce the interrupt and checkpoint state so the interrupted run can be resumed after the decision. If a privileged `create_agent` lacks either prerequisite, Trustabl can establish that the expected interrupt/resume control point is not structurally present at the constructor.

This check is intentionally narrower than claiming that any human review is good. A static scanner cannot establish that a reviewer read the underlying command, understood the consequence, or avoided rubber-stamping. LC-112 verifies a machine-checkable prerequisite for meaningful review; it does not certify reviewer cognition.

---

## Rule-by-rule defense

### LC-101 — Agent wires a code-execution or shell built-in tool (Severity: high, Confidence: 0.85, Fix type: code)

**What we detect:** a LangChain agent whose resolved hosted-tool set includes `PythonREPLTool`, `PythonAstREPLTool`, or `ShellTool`.

**Why it is flaggable:** these tools let model-selected input reach a Python interpreter or shell.

**Real-world consequence:** a prompt-injected agent can turn an ostensibly informational request into filesystem, credential, network, or process access available to the host process.

**Why severity is high:** arbitrary code/shell execution can directly cross confidentiality and integrity boundaries. Confidence is below 1.0 because some deployments isolate these tools in an external sandbox Trustabl cannot see.

**Fix type — code:** removing or replacing the privileged tool changes the agent's tool surface.

**Confidence 0.85:** out-of-band sandboxing can make a flagged capability materially safer than source structure alone suggests.

### LC-102 — AgentExecutor has no explicit max_iterations limit (Severity: low, Confidence: 0.6, Fix type: config)

**What we detect:** a Python `AgentExecutor` with no effective `max_iterations` kwarg.

**Why it is flaggable:** the workflow relies on a generic framework default rather than a task-sized bound.

**Real-world consequence:** a looping agent can spend unnecessary tool calls and cost before the default limit terminates it.

**Why severity is low:** LangChain supplies a default cap, so this is primarily explicitness and task-sizing hygiene.

**Fix type — config:** set `max_iterations` on the executor.

**Confidence 0.6:** external timeouts or deliberate reliance on the default are not visible to this predicate.

### LC-111 — TypeScript AgentExecutor has no explicit maxIterations limit (Severity: low, Confidence: 0.6, Fix type: config)

**What we detect:** a TypeScript `AgentExecutor` with no effective `maxIterations` option.

**Why it is flaggable / consequence:** same mechanism as LC-102 for LangChain.js.

**Why severity is low / Confidence 0.6:** same reasoning as LC-102.

**Fix type — config:** set `maxIterations` in the executor options.

### LC-112 — LangChain privileged create_agent lacks human-approval prerequisites (Severity: high, Confidence: 0.7, Fix type: config)

**What we detect:** a Python LangChain `CreateAgent` that wires `PythonREPLTool`, `PythonAstREPLTool`, or `ShellTool`, and either has no/empty `middleware` kwarg or has no effective `checkpointer` kwarg. The rule uses existing `agent_class`, `agent_uses_hosted_tool_class`, `agent_kwarg_list_empty`, and `agent_kwarg_missing` predicates.

**Why it is flaggable:** the model has a direct path to a high-impact execution capability, while the constructor lacks one or both structural prerequisites for an interrupt/resume human-approval flow. The missing boundary converts model selection into effect without an approval checkpoint visible to Trustabl.

**Real-world consequence:** an agent tasked with repository maintenance is given `ShellTool`. A prompt-injected issue asks it to run a destructive command. Without approval middleware/checkpointing, the model can invoke the shell in the same autonomous run instead of stopping for an authorization decision.

**Why severity is high and not critical:** arbitrary code/shell capability is high impact, but exploitation still depends on the model choosing/inheriting a harmful command and on the privileges of the runtime. Sandboxing or external controls may also constrain consequence.

**Fix type — config:** add human-in-the-loop approval middleware for the privileged tool and a checkpointer; the underlying tool implementation need not change.

**Confidence 0.7:** LC-112 checks the presence of middleware, not its class or policy. Non-empty unrelated middleware plus a checkpointer can silence the rule even though no approval occurs. Conversely, an external approval system not represented in `create_agent` kwargs can make a finding safer than it appears.

---

## What this policy does not cover

- LC-112 does not prove that `middleware` contains `HumanInTheLoopMiddleware` or that it gates every privileged tool.
- It does not measure whether a human sees raw action parameters, understands them, or merely rubber-stamps a model summary.
- External authorization services, proxy gates, or sandbox policies may not be visible to source-level constructor analysis.
- Legacy `create_react_agent` / raw `StateGraph` use different interrupt configuration and are intentionally out of scope for LC-112.
- Custom tools that independently reach code execution may not appear as the three hosted LangChain classes matched here.

---

## Recommendations beyond the fix

```python
from langchain.agents import create_agent
from langchain.agents.middleware import HumanInTheLoopMiddleware
from langgraph.checkpoint.memory import InMemorySaver
from langchain_experimental.tools import ShellTool

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

1. Prefer removing code/shell tools entirely when they are not required.
2. Sandbox privileged execution with minimal filesystem, network, credential, and process access.
3. Present the reviewer with the actual tool name and arguments, not only a model-written summary.
4. Log approval decisions and bind them to the exact proposed action so a changed action requires a new approval.
5. Add task-sized iteration/time limits in addition to approval boundaries.
