---
policy_id: crewai_side_effect_bounds
category: crewai
topic: side_effect_bounds
rules:
  - id: CREW-014
    severity: high
    confidence: 0.5
    scope: tool
    fix_type: code
references: [LLM06, LLM01]
---

# Policy Rationale: Unbounded Side-Effect Parameters

**Policy ID:** `crewai_side_effect_bounds`  
**File:** `crewai/side_effect_bounds.yaml`  
**Rules:** CREW-014  
**Severities:** high  
**Fix types:** code  
**References:** LLM06, LLM01

> **Read [openai_sdk/side_effect_bounds.md](../openai_sdk/side_effect_bounds.md) for the full threat model.**
> This document covers CrewAI-specific differences only.

---

## What this policy covers

A CrewAI tool (a function decorated with `@tool`, from `crewai` or `crewai_tools`) whose name signals a send/notify or refund/charge/pay/payout/transfer/issue action (`name_has_prefix`), paired with a free-form recipient or amount parameter the model supplies (`param_name_matches`), where the function body shows no visible bound (`not: has_body_text`). Same predicates and threat model as [openai_sdk/side_effect_bounds.md](../openai_sdk/side_effect_bounds.md), with **no** approval-gate clause because CrewAI has no tool-level one.

---

## Why unbounded side-effect parameters are a distinct concern in agent tools

Identical mechanism to the OpenAI case: a CrewAI tool's arguments come from the agent's own reasoning over its task, the crew's shared context, and other agents' outputs, which prompt injection or a poisoned upstream result can steer just as readily as in any other agent framework. See [openai_sdk/side_effect_bounds.md](../openai_sdk/side_effect_bounds.md#why-unbounded-side-effect-parameters-are-a-distinct-concern-in-agent-tools) for the full argument, including why this is distinct from CREW-006 (idempotency, a bounded 2× duplication).

---

## Rule-by-rule defense

### CREW-014 — Side-effecting tool lets the model choose the recipient or amount with no visible bound (Severity: high, Confidence: 0.5, Fix type: code)

**What we detect:**  
A CrewAI `@tool`-decorated function whose name starts with `send_` / `notify_` (paired with a parameter matching `to`, `cc`, `bcc`, `email`, `email_address`, `phone`, `phone_number`, `to_email`, `to_address`, `to_number`, or a name containing `recipient`), OR starts with `refund_` / `charge_` / `pay_` / `payout_` / `transfer_` / `issue_` (paired with a parameter matching `total`, `price`, a `cents`-suffixed name, or a name containing `amount`) — AND whose body/definition contains none of the shared Python bound-marker list (`le=`/`lt=`, `conint(`, `Literal[`, `MAX_`/`_LIMIT`, `ALLOWED`/`ALLOWLIST`, a domain-suffix check).

**Why it is flaggable:**  
Same mechanism as OAI-030: the name confirms a mutating verb, the parameter shape confirms the model supplies the recipient or amount directly, and the absence of a bound marker means the framework will execute the call with any value the model's reasoning produces.

**Real-world consequence:**  
A `charge_card(customer_id: str, amount_cents: int)` tool with no cap in its body, handed to a crew agent whose context includes a researcher agent's scraped web output: an injected instruction in the scraped text steers the agent's tool call to an amount nobody authorized.

**Why severity is high and not critical, and high and not medium:**  
Same reasoning as OAI-030 — plausible partial mitigations (a downstream API's own cap, review of the trace, controls configured outside the tool) rule out critical; an unbounded blast radius, versus a bounded small-multiple duplication for the idempotency family, rules out medium.

**Fix type — code:**  
The fix — a bound on the parameter, deriving the recipient from trusted context, or returning a proposed action for a human to confirm instead of executing — is a change to the tool's own definition or body.

**Confidence 0.5:**  
Tied with OAI-030/031, PYD-014, MCP-030, and LC-025 for the pack's floor. All of the confidence-gap scenarios in [openai_sdk/side_effect_bounds.md](../openai_sdk/side_effect_bounds.md#confidence-gap) apply directly.

**CrewAI-specific:** there is **no tool-level approval gate** for this rule to check. `Task(human_input=True)` asks a human to review the task's *final answer*, not each tool call, and it is configured on the task, not the tool — so it neither silences this rule nor actually stands between the model and the side effect. A tool that is otherwise gated by a custom wrapper elsewhere still fires.

---

## What this policy does not cover

All of the gaps in [openai_sdk/side_effect_bounds.md](../openai_sdk/side_effect_bounds.md#what-this-policy-does-not-cover) apply unchanged. CrewAI-specific additions:

- **Name.** CrewAI discovery names the tool by its *function* name, not the `@tool("Send Email")` display string, so a function named `run` decorated `@tool("Send Email")` is not matched.
- **`class X(BaseTool)` subclasses** are not discovered (a documented v1 gap shared with CREW-006), so a side-effecting tool implemented that way is not covered.
- **`Task(human_input=True)`, `Crew(...)` guardrails, or a `step_callback` that reviews calls** are invisible to a tool-scope rule; a tool gated that way still fires. This is a false-positive scenario, accepted rather than silenced because none of them is a per-call gate on the tool itself.

---

## Recommendations beyond the fix

```python
from crewai.tools import tool

MAX_REFUND_CENTS = 50_000  # $500.00


@tool("Refund payment")
def refund_payment(charge_id: str, amount_cents: int) -> str:
    """Propose a refund of up to MAX_REFUND_CENTS; a human executes it."""
    charge = payments_client.charges.retrieve(charge_id)
    if not 0 < amount_cents <= min(MAX_REFUND_CENTS, charge.amount):
        raise ValueError("refund outside the permitted range")
    return approval_queue.submit("refund", charge_id, amount_cents)
```

1. **Return a proposal, not an effect**, for anything above a low threshold; a queue a human drains is the only reliable gate CrewAI offers at the tool level.
2. **Enforce the same cap server-side**, independent of the tool's own check.
3. **Log every call with its resolved recipient/amount and the task ID.**
