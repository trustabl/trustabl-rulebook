---
policy_id: langchain_approvals
category: langchain
topic: approvals
rules:
  - id: LC-103
    severity: high
    confidence: 0.65
    scope: agent
    fix_type: config
references: [LLM06]
---

# Policy Rationale: LangChain Approval Gates

**Policy ID:** `langchain_approvals`  
**File:** `langchain/approvals.yaml`  
**Rules:** LC-103  
**Severity:** high  
**Fix type:** config  
**References:** LLM06 (Excessive Agency)

---

## What this policy covers

LC-103 targets modern LangChain v1 `create_agent` configurations, normalized by Trustabl as `CreateAgent`, that wire a known Python or shell execution tool and do not expose the visible prerequisites for LangChain's resumable human-review flow.

The rule fires when the agent uses `PythonREPLTool`, `PythonAstREPLTool`, or `ShellTool` and either the `middleware` list is missing or empty, or the `checkpointer` argument is missing.

## Threat mechanism

The failure mode is:

`model selects dangerous execution tool -> code/shell capability is reachable -> no visible resumable review boundary is configured -> action may execute before a human evaluates its concrete parameters`.

These execution tools can run model-selected Python or shell commands in the agent process. A human-review boundary can reduce the risk of prompt injection, confused-deputy behavior, or unintended high-impact execution by pausing the run before the action proceeds.

## Severity and confidence

**Severity: high.** Trustabl already treats wiring `PythonREPLTool`, `PythonAstREPLTool`, or `ShellTool` as a high-impact capability in LC-101. LC-103 focuses on the missing control boundary around that same capability.

**Confidence: 0.65.** Static analysis can verify the constructor structure, but it cannot prove that a non-empty middleware list actually contains `HumanInTheLoopMiddleware`, that its `interrupt_on` policy covers the dangerous tool, or that an equivalent approval layer exists elsewhere in the application. It also cannot determine whether a human meaningfully reviews the requested action.

## Example that fires

```python
from langchain.agents import create_agent
from langchain_experimental.tools import PythonREPLTool

agent = create_agent(
    model="openai:gpt-5",
    tools=[PythonREPLTool()],
)
```

The agent exposes Python execution but has no non-empty middleware configuration and no effective checkpointer.

## Safe implementation

```python
from langchain.agents import create_agent
from langchain.agents.middleware import HumanInTheLoopMiddleware
from langchain_experimental.tools import PythonREPLTool
from langgraph.checkpoint.memory import InMemorySaver

agent = create_agent(
    model="openai:gpt-5",
    tools=[PythonREPLTool()],
    middleware=[
        HumanInTheLoopMiddleware(
            interrupt_on={
                "python_repl": {
                    "allowed_decisions": ["approve", "reject"],
                }
            }
        )
    ],
    checkpointer=InMemorySaver(),
)
```

Pair the approval boundary with sandboxing, least privilege, restricted credentials, and execution timeouts.

## What this policy does not cover

This rule does not prove meaningful human oversight. In particular:

- unrelated middleware can satisfy the non-empty middleware structural check even when no human-review middleware is present;
- a custom `interrupt()`-based approval path may exist outside the constructor and remain invisible to this rule;
- an external policy engine, sandbox, or approval service may mitigate the risk without appearing in `create_agent`;
- custom high-impact tools are not classified by this rule;
- static analysis cannot determine whether a human actually read or understood the review prompt.

The strongest expected false positive is a project that enforces equivalent approval outside `create_agent`. The strongest expected false negative is a `create_agent` with arbitrary non-empty middleware and a checkpointer but no `HumanInTheLoopMiddleware` covering the dangerous tool.

## Relationship to LC-101

LC-101 detects the dangerous capability: the agent is wired to a Python or shell execution built-in. LC-103 detects a distinct control failure around that capability: a modern `CreateAgent` lacks the visible structural prerequisites for resumable human review.
