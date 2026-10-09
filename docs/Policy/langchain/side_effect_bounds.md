---
policy_id: langchain_side_effect_bounds
category: langchain
topic: side_effect_bounds
rules:
  - id: LC-115
    severity: medium
    confidence: 0.45
    scope: tool
    fix_type: code
references: [LLM06]
---

# Policy Rationale: LangChain / LangGraph Side-Effect Bounds

**Policy ID:** `langchain_side_effect_bounds`  
**File:** `langchain/side_effect_bounds.yaml`  
**Rules:** LC-115  
**Severities:** medium  
**Fix types:** code  
**References:** LLM06 (Excessive Agency)

> **Scope of this doc.** `side_effect_bounds.yaml` also ships LC-025 (free-form
> recipient / amount on a side-effecting tool), which predates this document and is
> not yet covered by a rationale doc — it is part of the standing rulebook-gate
> backlog and is deliberately not authored here. This doc defends LC-115 only.

---

## What this policy covers

**LC-115** targets a function registered as a LangGraph graph node —
`<builder>.add_node("name", func)` or `add_node(func)` — whose body shells out,
executes code, writes to disk, or calls a dynamically built URL, with no
`interrupt(...)` call in the body. Node functions are discovered as a distinct tool
kind (`langgraph_node`) because they are not `@tool`s and no tool-discovery pass
sees them.

---

## Why a graph node is a distinct side-effect surface

A `@tool` sits behind a tool-call boundary: the model proposes the call, the
framework dispatches it, and a guardrail, approval hook or human can see the action
before it runs. A LangGraph node has no such boundary — it executes automatically
every time the graph's edges reach it, and a conditional edge or loop can reach it
repeatedly. The only built-in way to stop a node and wait for a human is to call
`interrupt(...)` inside it (or compile the graph with `interrupt_before`), which
needs a checkpointer to resume.

So a node that shells out, writes files or fetches a model-influenced URL is
excessive agency (LLM06) with the approval step structurally absent: the state fed
to the node is produced by upstream LLM calls and tools, and a prompt injection that
steers the state reaches the side effect without anything pausing.

---

## Rule-by-rule defense

### LC-115 — LangGraph node performs a side effect with no interrupt() gate (Severity: medium, Confidence: 0.45, Fix type: code)

**What we detect:** a same-file, undecorated, top-level function registered through
`add_node` (kind `langgraph_node`) whose body satisfies any of `has_shell_call`,
`has_code_exec_call`, `has_write_call`, `has_dynamic_url_call` and does **not**
contain the text `interrupt(` (`not: has_body_text`). Discovery is import-gated to
the langchain / langgraph ecosystem; lambdas, methods, imported callables, decorated
functions and compiled subgraphs are not resolved.

**Why it is flaggable:** the listed calls are the engine's existing definition of a
side-effecting body, and a node runs unattended. The absence of `interrupt(` in the
body means the node itself offers no pause point before acting.

**Real-world consequence:** a `deploy` node that runs `subprocess.run(["make",
"deploy"])` executes on every pass through the graph; a poisoned upstream tool
result steers the state so the node deploys an attacker-chosen target with no
approval.

**Why severity is medium and not high:** the node's inputs are graph state, not
necessarily attacker-reachable, and many nodes are deliberate automation whose
trigger is gated upstream. The finding marks a missing gate, not a demonstrated
exploit. **Fix type — code:** the gate is an `interrupt(...)` call in the node (or
`interrupt_before=` on `compile`, which is a code change at the compile site).

**Confidence 0.45:** the lowest in the pack, deliberately. The rule reads only the
node's own body, so it cannot see an `interrupt()` earlier in the graph, an
`interrupt_before=["node"]` on `compile`, or an upstream node that already gates
entry — all of which legitimately silence the intent. It also over-fires on benign
file writes (a log, a cache) and calls `has_write_call` treats as writes.

---

## What this policy does not cover

- A node gated by `interrupt_before=` on `compile(...)`, or by an upstream
  approval node, is flagged anyway (the main false-positive class).
- Nodes registered as lambdas, bound methods, imported functions, decorated
  functions, or built with a factory are never discovered, so they are never
  checked.
- Side effects performed through a client library the body predicates do not model
  (an SDK call that sends a message, a database write) are invisible.
- A body that mentions `interrupt(` in a comment or string satisfies the silence
  check without gating anything.

---

## Recommendations beyond the fix

```python
from langgraph.types import interrupt

def deploy(state):
    approved = interrupt({"action": "deploy", "target": state["target"]})
    if not approved:
        return {"status": "skipped"}
    subprocess.run(["make", "deploy", state["target"]], check=True)
    return {"status": "deployed"}

app = builder.compile(checkpointer=PostgresSaver(conn))   # required for interrupt()
```

1. Call `interrupt(...)` before any irreversible side effect in a node, presenting
   the concrete action to the approver, and compile with a checkpointer (see LC-114).
2. Validate and allow-list the inputs a node takes from graph state before using
   them in a shell command, file path or URL.
3. Make side-effecting nodes idempotent: a replay after a crash or a loop edge
   should be harmless.
