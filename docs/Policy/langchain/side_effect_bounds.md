---
policy_id: langchain_side_effect_bounds
category: langchain
topic: side_effect_bounds
rules:
  - id: LC-025
    severity: high
    confidence: 0.5
    scope: tool
    fix_type: code
  - id: LC-115
    severity: medium
    confidence: 0.45
    scope: tool
    fix_type: code
references: [LLM06, LLM01]
---

# Policy Rationale: LangChain / LangGraph Side-Effect Bounds

**Policy ID:** `langchain_side_effect_bounds`  
**File:** `langchain/side_effect_bounds.yaml`  
**Rules:** LC-025, LC-115  
**Severities:** high, medium  
**Fix types:** code, code  
**References:** LLM06 (Excessive Agency), LLM01 (Prompt Injection)

> **Read [openai_sdk/side_effect_bounds.md](../openai_sdk/side_effect_bounds.md) for the full LC-025 threat model.**
> LC-115 is LangGraph-specific and is defended in full here.

---

## What this policy covers

**LC-025** targets a LangChain tool (the `@tool` decorator) whose name signals a **send/notify**
action or a **refund/charge/pay/payout/transfer/issue** money-moving action
(`name_has_prefix`), paired with a **free-form recipient or amount
parameter** the model supplies (`param_name_matches`), where the function
body shows **no visible bound** on that parameter (`not: has_body_text` —
`le=`/`lt=`, `conint(`/`condecimal(`/`confloat(`, `Literal[...]`, a `MAX_` /
`_LIMIT` constant, an `ALLOWED` / `ALLOWLIST` / `WHITELIST` name, a
domain-suffix check, or a call to `interrupt(`). Same predicates and threat
model as
[openai_sdk/side_effect_bounds.md](../openai_sdk/side_effect_bounds.md),
adapted to LangGraph's human-in-the-loop primitive in place of a decorator
kwarg.

**LC-115** targets a function registered as a LangGraph graph node —
`<builder>.add_node("name", func)` or `add_node(func)` — whose body shells out,
executes code, writes to disk, or calls a dynamically built URL, with no
`interrupt(...)` call in the body. Node functions are discovered as a distinct tool
kind (`langgraph_node`) because they are not `@tool`s and no tool-discovery pass
sees them.

---

## Why unbounded side-effect parameters are a distinct concern in agent tools

Identical mechanism to the OpenAI case, sharpened by the ReAct loop's
observation-driven reasoning: a LangChain tool's arguments come from the
model's interpretation of the conversation and any prior tool observations,
which prompt injection or a poisoned upstream result can steer just as
readily as in any other agent framework. See
[openai_sdk/side_effect_bounds.md](../openai_sdk/side_effect_bounds.md#why-unbounded-side-effect-parameters-are-a-distinct-concern-in-agent-tools)
for the full argument, including why this is distinct from LC-017
(idempotency, a bounded 2× duplication) and from LC-103's iteration cap
(volume, not reach).

LangChain-specific note: LangGraph's `interrupt(...)` function is the
framework's own human-in-the-loop primitive — calling it from inside a node
(including from inside a tool) pauses graph execution and surfaces a value
to the human operator, who must resume the graph (approving, denying, or
editing the pending action) before it continues. A tool has to *use*
`interrupt(...)` from its own body for this to count as a gate — unlike
OAI's `needs_approval`, there is no separate decorator kwarg to set, which
is why this rule checks the body rather than `Config`.

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

### LC-025 — Side-effecting tool lets the model choose the recipient or amount with no visible bound (Severity: high, Confidence: 0.5, Fix type: code)

**What we detect:**  
A LangChain `@tool`-decorated function whose name starts with `send_` /
`notify_` (paired with a parameter matching `to`, `cc`, `bcc`, `email`,
`email_address`, `phone`, `phone_number`, `to_email`, `to_address`,
`to_number`, or a name containing `recipient`), OR starts with `refund_` /
`charge_` / `pay_` / `payout_` / `transfer_` / `issue_` (paired with a
parameter matching `total`, `price`, a `cents`-suffixed name, or a name
containing `amount`) — AND whose function body contains none of the shared
Python bound-marker list AND no call to `interrupt(`.

**Why it is flaggable:**  
Same mechanism as OAI-030: the name confirms a mutating verb, the parameter
shape confirms the model supplies the recipient or amount directly, and the
absence of both a bound marker and an `interrupt(...)` call means the
ReAct loop can execute this tool with any value the model's reasoning
produces, with no checkpoint before it runs.

**Real-world consequence:**  
A `charge_card(customer_id: str, amount_cents: int)` tool with no cap
anywhere in its body and no `interrupt(...)` call, wired into an
AgentExecutor whose observations include content from a prior
document-retrieval step: an injected instruction embedded in a retrieved
document steers the agent's next tool call to an amount the caller never
authorized.

**Why severity is high and not critical, and high and not medium:**  
Same reasoning as OAI-030 — plausible partial mitigations (a downstream
API's own cap, a LangGraph-level guard node checking the pending action
before it reaches this tool, human review of the trace) rule out critical;
an unbounded blast radius, versus a bounded small-multiple duplication for
the idempotency family, rules out medium.

**Fix type — code:**  
The fix — a Pydantic field constraint on the tool's `args_schema`, deriving
the recipient from trusted context, or adding an `interrupt(...)` call — is
a change to the tool's own definition or body.

**Confidence 0.5:**  
Tied with OAI-030/031/PYD-014/MCP-030 for the pack's floor. All of the
confidence-gap scenarios in
[openai_sdk/side_effect_bounds.md](../openai_sdk/side_effect_bounds.md#confidence-gap)
apply directly, with one LangChain-specific addition: **the `args_schema`
class shape.** LangChain tools idiomatically declare their parameter
constraints on a separate Pydantic `BaseModel` passed as `args_schema=`
(`StructuredTool.from_function(fn, args_schema=RefundInput)`, or `@tool(
args_schema=RefundInput)`) rather than inline in the decorated function's
own signature. Discovery's parameter names still come from the wrapped
function `fn`'s own signature either way (`args_schema` only flips
`HasTypedParams`), but the bound-marker body-text scan walks only the
wrapped function's own body — never the separate `BaseModel` class — so a
`Field(le=...)` constraint declared on that class, which is exactly where
this framework's idiom puts it, is structurally invisible to this rule. This
is the same "bound lives in a separate class" gap the primary doc names, but
it is the *default* idiom in LangChain rather than an occasional pattern,
which is part of why this rule's confidence sits at the pack floor for this
SDK specifically.

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

### LC-025

All of the gaps in
[openai_sdk/side_effect_bounds.md](../openai_sdk/side_effect_bounds.md#what-this-policy-does-not-cover)
apply unchanged. LangChain-specific additions:

- **`args_schema`-class bounds**, as discussed above in the confidence gap
  — the single largest LangChain-specific blind spot, since it is the
  framework's own idiomatic way to constrain tool arguments.
- **`interrupt(...)` called but its return value ignored, or called on an
  unrelated branch.** The predicate checks only for the substring's
  presence anywhere in the function body, not that the specific
  recipient/amount value is what gets confirmed, or that the tool actually
  halts when the human declines.
- **A LangGraph checkpointer or a graph-level guard node** that intercepts
  the pending tool call before it executes, entirely outside the tool
  function's own source, is invisible to this rule.
- **`class X(BaseTool)` subclasses.** Discovery's LangChain tool coverage is
  documented as strongest for the `@tool` decorator and the `Tool(fn)`
  factory; the `BaseTool` subclass shape is a known v1 discovery gap shared
  with LC-017 and the rest of this pack's LangChain rules, so a
  side-effecting tool implemented that way is not covered by LC-025 either.

### LC-115

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

### For LC-025

```python
from typing import Annotated

from langchain_core.tools import tool
from langgraph.types import interrupt
from pydantic import BaseModel, Field

MAX_REFUND_CENTS = 50_000  # $500.00


class RefundInput(BaseModel):
    charge_id: str
    amount_cents: Annotated[int, Field(gt=0, le=MAX_REFUND_CENTS)]


@tool(args_schema=RefundInput)
def refund_payment(charge_id: str, amount_cents: int) -> dict:
    """Refund up to MAX_REFUND_CENTS of a previously captured charge.

    Pauses for human approval via interrupt() before executing; the
    args_schema bound is a defense-in-depth ceiling, not the only control.
    """
    charge = payments_client.charges.retrieve(charge_id)
    if amount_cents > charge.amount:
        raise ValueError("refund cannot exceed the original charge amount")

    approved = interrupt(
        {"action": "refund", "charge_id": charge_id, "amount_cents": amount_cents}
    )
    if not approved:
        raise PermissionError("refund not approved")

    return payments_client.refunds.create(
        charge=charge_id,
        amount=amount_cents,
        idempotency_key=f"refund:{charge_id}:{amount_cents}",
    )
```

Additional hardening the rule cannot detect but materially reduces risk:

1. **Branch on the `interrupt(...)` resume value.** Calling `interrupt(...)`
   is not a gate unless the tool actually halts the side effect when the
   human declines or edits the pending action.
2. **Prefer a graph-level guard node for high-risk tools** over relying on
   every tool author to remember to call `interrupt(...)` individually —
   centralizing the check is more robust than per-tool discipline.
3. **Enforce the same cap server-side**, independent of the `args_schema`
   constraint, so a differently-shaped call path cannot bypass it.
4. **Log every side-effecting call with its resolved recipient/amount and
   the run/thread ID**, so a steered call is auditable via the LangGraph
   trace regardless of what caught (or missed) it.

### For LC-115

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
