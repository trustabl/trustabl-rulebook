---
policy_id: autogen_side_effect_bounds
category: autogen
topic: side_effect_bounds
rules:
  - id: AG2-020
    severity: high
    confidence: 0.5
    scope: tool
    fix_type: code
references: [LLM06, LLM01]
---

# Policy Rationale: Unbounded Side-Effect Parameters

**Policy ID:** `autogen_side_effect_bounds`  
**File:** `autogen/side_effect_bounds.yaml`  
**Rules:** AG2-020  
**Severities:** high  
**Fix types:** code  
**References:** LLM06, LLM01

> **Read [openai_sdk/side_effect_bounds.md](../openai_sdk/side_effect_bounds.md) for the full threat model.**
> This document covers AutoGen / AG2-specific differences only.

---

## What this policy covers

An AutoGen / AG2 tool function — one decorated `@<agent>.register_for_llm(...)` / `register_for_execution()`, or passed to `register_function(fn, caller=..., executor=...)` — whose name signals a send/notify or refund/charge/pay/payout/transfer/issue action (`name_has_prefix`), paired with a free-form recipient or amount parameter (`param_name_matches`), where the function body shows no visible bound (`not: has_body_text`). Same predicates and threat model as [openai_sdk/side_effect_bounds.md](../openai_sdk/side_effect_bounds.md), with **no** approval-gate clause because AutoGen has no tool-level one.

---

## Why unbounded side-effect parameters are a distinct concern in agent tools

Identical mechanism to the OpenAI case: an AutoGen tool's arguments are produced by the assistant agent's reasoning over the whole multi-agent conversation, which prompt injection or a poisoned upstream result can steer just as readily as in any other agent framework. See [openai_sdk/side_effect_bounds.md](../openai_sdk/side_effect_bounds.md#why-unbounded-side-effect-parameters-are-a-distinct-concern-in-agent-tools) for the full argument, including why this is distinct from AG2-015 (idempotency, a bounded 2× duplication).

---

## Rule-by-rule defense

### AG2-020 — Side-effecting tool lets the model choose the recipient or amount with no visible bound (Severity: high, Confidence: 0.5, Fix type: code)

**What we detect:**  
A AutoGen / AG2 tool function (registered via `register_for_llm` / `register_for_execution` or `register_function(...)`) whose name starts with `send_` / `notify_` (paired with a parameter matching `to`, `cc`, `bcc`, `email`, `email_address`, `phone`, `phone_number`, `to_email`, `to_address`, `to_number`, or a name containing `recipient`), OR starts with `refund_` / `charge_` / `pay_` / `payout_` / `transfer_` / `issue_` (paired with a parameter matching `total`, `price`, a `cents`-suffixed name, or a name containing `amount`) — AND whose body/definition contains none of the shared Python bound-marker list (`le=`/`lt=`, `conint(`, `Literal[`, `MAX_`/`_LIMIT`, `ALLOWED`/`ALLOWLIST`, a domain-suffix check).

**Why it is flaggable:**  
Same mechanism as OAI-030: the name confirms a mutating verb, the parameter shape confirms the model supplies the recipient or amount directly, and the absence of a bound marker means the framework will execute the call with any value the model's reasoning produces.

**Real-world consequence:**  
A `transfer_funds(account_id: str, amount: float)` function registered with `register_for_llm` on an assistant agent, executed by a `UserProxyAgent` with `human_input_mode="NEVER"`: any message in the group chat, including another agent's injected instruction, steers the transfer to an arbitrary amount.

**Why severity is high and not critical, and high and not medium:**  
Same reasoning as OAI-030 — plausible partial mitigations (a downstream API's own cap, review of the trace, controls configured outside the tool) rule out critical; an unbounded blast radius, versus a bounded small-multiple duplication for the idempotency family, rules out medium.

**Fix type — code:**  
The fix — a bound on the parameter, deriving the recipient from trusted context, or requiring human input on the executing agent — is a change to the tool's own body or to how it is registered.

**Confidence 0.5:**  
Tied with OAI-030/031, PYD-014, MCP-030, and LC-025 for the pack's floor. All of the confidence-gap scenarios in [openai_sdk/side_effect_bounds.md](../openai_sdk/side_effect_bounds.md#confidence-gap) apply directly.

**AutoGen-specific:** there is **no tool-level approval gate**. `human_input_mode` is set on the *executing agent*, not on the tool, so this rule cannot see it (AG2-002 separately covers the `NEVER` + code-execution case). A tool executed by an agent with `human_input_mode="ALWAYS"` still fires.

---

## What this policy does not cover

All of the gaps in [openai_sdk/side_effect_bounds.md](../openai_sdk/side_effect_bounds.md#what-this-policy-does-not-cover) apply unchanged. AutoGen / AG2-specific additions:

- **autogen_core `FunctionTool`** (the v0.4 shape) and AG2 `@tool` are not discovered (documented v1 gaps), so tools defined that way are not covered.
- **`register_function` with a function from another module** is not resolved; only a same-file top-level function is.
- **`human_input_mode="ALWAYS"` / `"TERMINATE"` on the executor, or a human-approval agent in the chat**, is invisible to a tool-scope rule; a tool gated that way still fires.

---

## Recommendations beyond the fix

```python
MAX_TRANSFER = 500


def transfer_funds(account_id: str, amount: float) -> str:
    """Transfer up to MAX_TRANSFER to a pre-registered account."""
    if account_id not in registered_accounts(current_user()):
        raise PermissionError("unknown destination")
    if not 0 < amount <= MAX_TRANSFER:
        raise ValueError("amount outside the permitted range")
    return bank.transfer(account_id, amount)


user_proxy = UserProxyAgent("executor", human_input_mode="ALWAYS")
register_function(transfer_funds, caller=assistant, executor=user_proxy,
                  description="Transfer funds")
```

1. **Run the executor with `human_input_mode="ALWAYS"`** for money-moving or messaging tools so a person sees the resolved arguments.
2. **Enforce the same cap server-side.**
3. **Log every call with the resolved recipient/amount and the conversation ID.**
