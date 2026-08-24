---
policy_id: langchain_idempotency
category: langchain
topic: idempotency
rules:
  - id: LC-009
    severity: medium
    confidence: 0.55
    scope: tool
    fix_type: code
  - id: LC-016
    severity: medium
    confidence: 0.5
    scope: tool
    fix_type: code
references: [LLM06]
---

# Policy Rationale: LangChain Mutating-Tool Idempotency

**Policy ID:** `langchain_idempotency`  
**File:** `langchain/idempotency.yaml`  
**Rules:** LC-009, LC-016  
**Severities:** medium, medium  
**Fix types:** code, code  
**References:** LLM06 (Excessive Agency)

> Shares the mutating-tool idempotency threat model with
> [crewai/idempotency.md](../crewai/idempotency.md) and
> [claude_sdk/idempotency.md](../claude_sdk/idempotency.md). LangChain-specific
> angle only.

---

## What this policy covers

LangChain / LangGraph tools whose name implies a side effect but which take no
idempotency key.

**LC-009** (Python) fires when an `@tool` / `StructuredTool` / `Tool` function's
name starts with one of `create_`, `send_`, `delete_`, `post_`, `update_`,
`refund_`, `charge_`, `issue_` (predicate `name_has_prefix`) AND no parameter
name contains `idempot` or is exactly `request_id` / `txn_id` (predicate
`param_name_matches`, negated).

**LC-016** (TypeScript) is the LangChain.js counterpart: the same mutation
prefixes without the trailing underscore (so `createCharge` matches `create`),
and the key is looked up on the Zod schema (`idempotencyKey`, `requestId`,
`txnId`, plus the snake_case spellings).

Both are name-and-signature heuristics — they do not read the tool body.

---

## Why missing idempotency is a distinct concern in LangChain tools

A mutating tool that runs twice does its side effect twice: a duplicate charge,
a double-sent message, a repeated delete. In ordinary code a developer controls
how often a function is called; in a LangChain agent the *framework* re-invokes
tools. AgentExecutor retries under timeouts and ambiguous `ToolMessage`s, and
LangGraph's `ToolNode` can re-select the same tool across turns — so the same
side-effecting action can fire more than once without the author writing any
retry logic. The classic trigger is a timeout: the backend processed the
request but the response was lost, so from the agent's side the call "failed"
and is retried, and the action happens again.

LC-102's `max_iterations` (and LC-111's `maxIterations`) do not close this.
Those rules cap how many *steps* the executor takes, not whether one mutating
step is safe to retry. A two-step agent that charges once, times out, and
retries still double-charges inside a `max_iterations=15` budget.

An idempotency key closes this: the tool sends a stable key the backend uses to
recognize a retried request and return the original result instead of
re-executing. Without it, the agent's own retry behavior turns a transient
network blip into a duplicated real-world effect. This is an excessive-agency
(LLM06) reliability hazard. The protection only holds end to end if the
downstream service also honors the key; the parameter is necessary but not
sufficient on its own.

---

## Rule-by-rule defense

### LC-009 — Mutating LangChain tool has no idempotency key (Severity: medium, Confidence: 0.55, Fix type: code)

**What we detect:** a Python LangChain tool whose name begins with a mutation
prefix (`create_`, `send_`, `refund_`, …) and which has no parameter named for
an idempotency key (`*idempot*`, `request_id`, or `txn_id`).

**Why it is flaggable:** the name signals a side effect, and LangChain's retry
and re-selection behavior can fire that side effect twice; without a key there
is no mechanism for the backend to deduplicate.

**Real-world consequence:** a `charge_card(customer, amount)` tool times out
after the charge succeeds; AgentExecutor retries, and the customer is charged
twice with no key for the payment processor to collapse the duplicate.

**Why severity is medium and not high:** the duplicate fires only on a retry
path (timeout or ambiguous failure), not on every call, and many backends are
already idempotent for other reasons — so the impact is real but probabilistic
rather than guaranteed.

**Fix type — code:** adding an `idempotency_key` parameter and threading it to
the API is a tool-source change.

**Confidence 0.55:** this is a name heuristic, so a tool named `update_cache`
that mutates nothing fires (false positive), a side-effecting tool named
`process_payment` without a mutation prefix does not (false negative), and a
tool that achieves idempotency through an unnamed mechanism (a natural key in
the body) is over-flagged.

### LC-016 — TypeScript LangChain mutating tool has no idempotency key (Severity: medium, Confidence: 0.5, Fix type: code)

**What we detect:** a LangChain.js `tool()` / `DynamicStructuredTool` whose
`name` starts with a mutation prefix (`create`, `send`, `delete`, … — no
trailing underscore, so both `create_charge` and `createCharge` match) and
whose Zod schema has no parameter whose name contains `idempot` or is exactly
`requestId` / `request_id` / `txnId` / `txn_id`.

**Why it is flaggable / consequence:** identical to LC-009 in LangChain.js.
AgentExecutor and LangGraph re-invoke the tool; without a schema field the
model cannot even *pass* a key.

**Severity medium:** same profile as LC-009.

**Fix type — code:** adding an `idempotencyKey` field to the Zod schema and
forwarding it is a source edit.

**Confidence 0.5:** five points below LC-009 because the prefix match is
looser (bare `create` matches `createReport` that only renders a PDF) and
because a key threaded as a captured closure / env var rather than a schema
field is invisible to `param_name_matches`.

---

## What this policy does not cover

- Side-effecting tools whose name does not start with a listed prefix
  (`process_`, `apply_`, `submit_`, `transfer_`) — they are false negatives.
- Tools that achieve idempotency without a matching parameter name — e.g. by
  deriving a natural key inside the body, or because the backend dedupes on a
  business field. The signature heuristic cannot see body logic, so these fire
  anyway.
- Read-only tools that happen to match a prefix (`update_view_count` that only
  reads) — a false positive.
- Whether the downstream service actually honors the key. The rule checks for a
  parameter, not that retries are truly deduplicated end to end.
- Tools whose name lives only on the agent `tools` record key (LangChain.js
  sometimes binds tools without a `name` field) — `name_has_prefix` reads
  `ToolDef.Name`.

---

## Recommendations beyond the fix

```python
from langchain_core.tools import tool

@tool
def charge_card(customer_id: str, amount_cents: int, idempotency_key: str) -> str:
    """Charge a customer. `idempotency_key` must be stable across retries so a
    re-sent request is collapsed by the processor instead of charging twice."""
    return payments.charge(
        customer=customer_id,
        amount=amount_cents,
        idempotency_key=idempotency_key,   # backend dedupes on this
    )
```

```typescript
import { tool } from "@langchain/core/tools";
import { z } from "zod";

export const chargeCard = tool(
  async ({ customerId, amountCents, idempotencyKey }) => {
    return payments.charge({
      customer: customerId,
      amount: amountCents,
      idempotencyKey,
    });
  },
  {
    name: "chargeCard",
    description:
      "Charge a customer. idempotencyKey must be stable across retries.",
    schema: z.object({
      customerId: z.string(),
      amountCents: z.number(),
      idempotencyKey: z.string(),
    }),
  },
);
```

1. Add an `idempotency_key` / `idempotencyKey` parameter to every mutating tool
   and pass it through to the backing API so a retried call is recognized and
   deduplicated.
2. Make the key stable for a logical operation — derive it from the operation's
   inputs (e.g. a hash of customer + amount + intent) so the same retried
   action reuses the same key.
3. Confirm the downstream service honors the key; an idempotency parameter the
   backend ignores gives no protection.
4. Where the backend cannot dedupe, guard at the application layer (a
   processed-operations table keyed by the idempotency key) before performing
   the side effect.
