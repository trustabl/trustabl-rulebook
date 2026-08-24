---
policy_id: langchain_idempotency
category: langchain
topic: idempotency
rules:
  - id: LC-008
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
**Rules:** LC-008, LC-016  
**Severities:** medium, medium  
**Fix types:** code, code  
**References:** LLM06 (Excessive Agency)

> **Read [claude_sdk/idempotency.md](../claude_sdk/idempotency.md) and
> [crewai/idempotency.md](../crewai/idempotency.md) for the shared threat
> model** (timeout double-spend, name-heuristic confidence, backend must honor
> the key). This document covers the LangChain-specific retry surfaces and the
> Python/TypeScript split.

---

## What this policy covers

LangChain / LangGraph tools whose name implies a side effect but which take no
idempotency key. Discovery already records `ToolDef.Name` and `ToolDef.ParamNames`
for `@tool`-decorated Python functions, `StructuredTool` constructors, and
LangChain.js `tool(...)` factories (including Zod object keys). These rules are a
name-and-signature heuristic over that record — they do not walk the tool body
and they do not inspect whether a downstream API actually dedupes.

**LC-008** (Python) fires when the tool name starts with one of `create_`,
`send_`, `delete_`, `post_`, `update_`, `refund_`, `charge_`, `issue_`
(predicate `name_has_prefix`) AND no parameter name contains `idempot` or is
exactly `request_id` / `txn_id` (predicate `param_name_matches`, negated). The
trailing underscore matches snake_case Python names (`create_order`,
`charge_card`).

**LC-016** (TypeScript) uses the same predicates with a bare prefix set
(`create`, `send`, …, no trailing underscore) so `createCharge` and
`create_charge` both match, and adds camelCase exact names `requestId` /
`txnId` alongside the snake_case spellings. `applies_to` is `[langchain_tool]`
only — this is not a widening of CSDK-006 / CREW-006 / PYD-007.

The match block is the same pair already shipping on Claude (CSDK-006 / CSDK-016),
CrewAI (CREW-006), and Pydantic AI (PYD-007). No new engine predicate is required.

---

## Why missing idempotency is a distinct concern in LangChain tools

A mutating tool that runs twice does its side effect twice: a duplicate charge,
a double-sent message, a repeated delete. In ordinary application code the
caller controls how often a function is invoked. In a LangChain agent the
*framework* re-invokes tools, and it does so on more than one surface:

1. **The model re-selects the tool.** After an inconclusive, truncated, or
   oddly-shaped result, the next agent step often calls the same tool with the
   same arguments. That is not an HTTP retry library — it is the ReAct /
   tool-calling loop doing what it is designed to do.
2. **AgentExecutor retries.** Legacy `AgentExecutor` re-issues a tool step after
   a timeout, a parse failure (`handle_parsing_errors`), or an ambiguous
   exception. The default `max_iterations=15` (the gap LC-102 flags when it is
   left implicit) caps how many *steps* the loop takes. It does not make a
   single mutating step safe to run twice. A graph that is "bounded" at 15 can
   still double-charge on step 3.
3. **LangGraph tool nodes.** `create_react_agent` / `create_agent` and a raw
   `StateGraph` with a tool node re-run the node when the previous invocation
   timed out or when a checkpoint is replayed. At-least-once delivery is the
   common case: the backing API committed, the acknowledgement was lost, the
   node runs again.
4. **TypeScript `createReactAgent` / `AgentExecutor`.** The same loop exists in
   LangChain.js. The Zod schema is what the model fills; if it has no
   idempotency field, neither the model nor the graph has a key to send.

The classic failure is the timeout double-spend: `charge_card` succeeds, the
HTTP client times out, AgentExecutor or the graph retries, and the customer is
billed twice. An idempotency key closes this only if it is (a) present on the
tool signature the model is asked to fill, (b) stable across retries of the
same logical action, and (c) honored by the downstream service. The rule can
only check (a). That is why confidence is deliberately low — same calibration
as CSDK-006 (0.55) and CSDK-016 (0.5).

This is OWASP LLM06 (Excessive Agency): the agent can cause a real-world effect
more times than the user intended. It is a reliability finding with a security
shape, not a prompt-injection finding. Prompt injection can *cause* a retry, but
the defect is the missing dedupe, not the injection itself.

LangChain is the right place to land this port. The pack already covers shell,
SSRF, code-exec, `return_direct`, and `max_iterations`. It did not cover
idempotency, even though AgentExecutor / LangGraph are among the most retry-heavy
orchestrators in the ecosystem. CrewAI and Pydantic AI already ship the Python
half; Claude already ships the Python+TS pair. LC-008 / LC-016 close that hole
with existing predicates.

---

## Rule-by-rule defense

### LC-008 — Mutating LangChain tool has no idempotency key (Severity: medium, Confidence: 0.55, Fix type: code)

**What we detect:**
A Python LangChain tool (`applies_to: [langchain_tool]`) whose name begins with
a mutation prefix (`create_`, `send_`, `delete_`, `post_`, `update_`,
`refund_`, `charge_`, `issue_`) and whose parameter names contain no
idempotency-key-shaped token (`contains: [idempot]`, `exact: [request_id,
txn_id]`). Predicates: `name_has_prefix` AND `not param_name_matches`. Prefix
matching is case-insensitive. This is a name-and-signature heuristic over
`ToolDef.Name` / `ToolDef.ParamNames`; the body is not read.

**Why it is flaggable:**
The name signals a side effect, and LangChain's AgentExecutor / LangGraph /
model-reselection behavior can fire that side effect twice. Without a key on
the signature there is nothing for the model to pass and nothing for the
backend to collapse. LC-102's `max_iterations` finding is a different axis: a
bounded loop can still duplicate one mutating step.

**Real-world consequence:**
A `@tool` named `create_order(customer_id, amount)` is invoked; the payments
API charges the card and the HTTP client times out before the tool returns.
AgentExecutor retries the same call. The customer is charged twice, and there
is no key for the processor to treat the second request as a replay.

**Why severity is medium and not high:**
The duplicate fires only on a retry or re-selection path, not on every call,
and many backends already dedupe by natural key (order id, Stripe's own
idempotency layer). The impact is real but probabilistic. It is not low:
when the retry does happen, the effect is a user-visible wrong action
(double charge, double email, repeated delete), not a log line.

**Fix type — code:**
Adding `idempotency_key: str` to the tool signature and threading it to the
backing API is a tool-source change. There is no AgentExecutor / graph
constructor flag that supplies this.

**Confidence 0.55:**
Same number as CSDK-006 / CREW-006 / PYD-007, on purpose. This is a name
heuristic, so three gaps are priced in:

- **False positive:** `update_cache` / `create_summary` match a prefix but
  mutate nothing (or only in-memory state). A tool that is already idempotent
  because the backend dedupes on `order_id` still fires, because the parameter
  is not named `idempot*` / `request_id` / `txn_id`.
- **False negative:** `process_payment`, `submit_invoice`, `transfer_funds`,
  `apply_refund` are mutating and have no matching prefix, so they stay silent.
- **Unnamed mechanism:** a tool that hashes `(customer, amount, date)` inside
  the body and sends that as a key is safe in production and still fires,
  because the heuristic cannot see the body.

Treat every hit as a review prompt for a side-effecting tool, not as a defect
certificate. The 0.55 is the honest number for that contract.

### LC-016 — TypeScript LangChain mutating tool has no idempotency key (Severity: medium, Confidence: 0.5, Fix type: code)

**What we detect:**
A LangChain.js `tool(...)` (`language: typescript`, `applies_to:
[langchain_tool]`) whose `name` begins with a bare mutation prefix (`create`,
`send`, `delete`, `post`, `update`, `refund`, `charge`, `issue`) and whose
Zod-schema parameter names contain no idempotency-key-shaped token
(`contains: [idempot]`, `exact: [requestId, request_id, txnId, txn_id]`).
Same predicate pair as LC-008. The prefix set is bare (no trailing
underscore) so both `create_charge` and idiomatic `createCharge` match —
`name_has_prefix` is a literal, case-insensitive string-prefix test against
`ToolDef.Name`. The exact-name list adds the camelCase `requestId` / `txnId`
spellings that LC-008 does not carry. Discovery populates `ParamNames` from
the Zod object keys; the handler body is not inspected.

**Why it is flaggable:**
A mutating tool with no dedupe field on the Zod schema cannot tell a retry
from a new request. `createReactAgent` / `AgentExecutor` / a LangGraph.js tool
node will re-invoke it after a timeout or an inconclusive result, and the
model has no key to reuse. The mechanism is the same as
[LC-008](#lc-008--mutating-langchain-tool-has-no-idempotency-key-severity-medium-confidence-055-fix-type-code);
the Zod schema is the TypeScript equivalent of the Python signature the model
fills.

**Real-world consequence:**
`tool(..., { name: "createCharge", schema: z.object({ amount: z.number() }) })`
times out after Stripe accepted the charge; `createReactAgent` retries; the
card is charged twice. A `sendInvoice` tool with no `idempotencyKey` in the
schema sends the invoice twice.

**Why severity is medium and not high:**
Same as LC-008 — real damage, but conditional on a retry actually occurring
and on the downstream API not already deduping. Not low, because a hit that
is a true positive is a user-visible wrong action.

**Fix type — code:**
Adding `idempotencyKey: z.string()` (or `requestId`) to the tool's Zod schema
and threading it to the backend is an edit to the tool's own source.

**Confidence 0.5:**
One notch below LC-008, matching CSDK-016, because the bare prefix set widens
both error modes.

- **False positives:** `createSummary` (returns text), `updatedAt`-style
  helpers, `issueDescription`, `postProcess` that only transforms data; a
  Stripe-style API that honors an idempotency header the tool never names
  makes the runtime safe while the signature still fires.
- **False negatives:** mutating tools named `book`, `apply`, `pay`,
  `transfer`, `submit` sit outside the prefix set. An idempotency field
  spelled `dedupeKey` or `clientToken` is not recognized, so a *safe* tool
  still fires — the inverse of a false positive, same root cause.

Treat every hit as a review prompt, not a defect.

---

## What this policy does not cover

- Side-effecting tools whose name does not start with a listed prefix
  (`process_`, `apply_`, `submit_`, `transfer_`, `book`, `pay`) — false
  negatives on genuinely unsafe tools.
- Tools that achieve idempotency without a matching parameter name — a natural
  key derived in the body, a backend that dedupes on `order_id`, a Stripe
  SDK that injects its own key. The signature heuristic cannot see those, so
  they fire anyway (false positives).
- Read-only tools that happen to match a prefix (`update_view_count` that only
  reads, `create_report` that returns a string) — false positives.
- Whether the downstream service actually honors the key. The rule checks for
  a parameter, not that retries are deduplicated end to end. A key that is
  accepted and ignored is a passing scan and a still-duplicated charge.
- Whether the model reuses the same key on retry. A fresh UUID generated
  inside the tool on every call defeats the parameter the rule asked for.
- Non-retry duplication: the model deliberately calling the tool twice for two
  distinct actions. Idempotency keys do not prevent that; they prevent
  *indistinguishable* retries.
- Graph-level retry policy configuration (`RetryPolicy` on a LangGraph node,
  `max_retries` on a tool wrapper). Those are worthwhile, but they are not
  this predicate, and a retry policy without a key still double-fires.
- HTTP-without-timeout (the LC-007 / LC-015 family). Timeouts *cause* some of
  the retries this rule cares about; they are a separate detection.
- Uncaught `raise` / missing try/except (the error-handling family). A tool
  that raises can trigger a retry; that is a separate predicate (`has_raise`).

---

## Recommendations beyond the fix

```python
from langchain_core.tools import tool

@tool
def create_order(customer_id: str, amount_cents: int, idempotency_key: str) -> dict:
    """Create and charge an order. `idempotency_key` must be stable across
    retries of the same logical order so a re-sent request is collapsed by
    the processor instead of charging twice."""
    return payments.charge(
        customer=customer_id,
        amount=amount_cents,
        idempotency_key=idempotency_key,  # backend dedupes on this
    )
```

```typescript
import { tool } from "@langchain/core/tools";
import { z } from "zod";

export const createCharge = tool(
  async ({ amount, idempotencyKey }) =>
    payments.charge({ amount, idempotencyKey }),
  {
    name: "createCharge",
    description:
      "Charge a card. Reuse the same idempotencyKey when retrying the same logical charge.",
    schema: z.object({
      amount: z.number(),
      idempotencyKey: z.string(),
    }),
  },
);
```

1. Add an `idempotency_key` / `idempotencyKey` parameter to every mutating
   tool and pass it through to the backing API so a retried call is
   recognized and deduplicated.
2. Make the key stable for a logical operation — derive it from the
   operation's inputs (for example a hash of customer + amount + intent) so
   the same retried action reuses the same key. Do not generate a fresh UUID
   inside the tool on every invocation.
3. Document in the tool description that the model must reuse the *same* key
   when retrying the same logical action and a fresh key for a genuinely new
   one. The schema field is what the model sees.
4. Confirm the downstream service honors the key. An idempotency parameter
   the backend ignores gives no protection. Prefer APIs that treat a repeated
   key as a replay (return the original result) rather than a conflict error
   the agent will then "fix" by trying again with a new key.
5. Where the backend cannot dedupe, guard at the application layer (a
   processed-operations table keyed by the idempotency key) *before*
   performing the side effect.
6. Do not treat `max_iterations` / `maxIterations` (LC-102 / LC-111) as a
   substitute. Cap the loop *and* make each mutating step replay-safe.
