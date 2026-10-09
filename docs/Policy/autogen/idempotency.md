---
policy_id: autogen_idempotency
category: autogen
topic: idempotency
rules:
  - id: AG2-015
    severity: medium
    confidence: 0.55
    scope: tool
    fix_type: code
references: [LLM06]
---

# Policy Rationale: AutoGen Mutating-Tool Idempotency

**Policy ID:** `autogen_idempotency`  
**File:** `autogen/idempotency.yaml`  
**Rules:** AG2-015  
**Severities:** medium  
**Fix types:** code  
**References:** LLM06 (Excessive Agency)

> Shares the at-least-once threat model with
> [openai_sdk/idempotency.md](../openai_sdk/idempotency.md). AutoGen-specific
> angle only.

---

## What this policy covers

An AutoGen / AG2 registered tool whose name begins with a mutating verb —
`create_`, `send_`, `delete_`, `post_`, `update_`, `refund_`, `charge_`,
`issue_` — and which declares no parameter that looks like a deduplication key
(`*idempot*`, `request_id`, `txn_id`).

---

## Why idempotency is a distinct concern in agent tools

A retry is not an unusual event in an agent; it is the normal response to an
ambiguous result. The model re-invokes a tool whose output it could not
interpret, and it has no way to know whether the first call's side effect
committed before the response was lost. That is at-least-once delivery with a
language model as the retry policy, and the retry policy cannot inspect the
remote's state.

AutoGen adds two further retry paths that a single-agent loop does not have, and
both come from its conversation model rather than from the tool.

The first is persistence. A tool response is a message appended to the
conversation, and that conversation is re-sent in full to the model on every
later turn. A call whose result read as inconclusive does not scroll out of
reach — it stays in front of the model, alongside its arguments, for the rest of
the run. The window in which a duplicate can fire is not the next turn; it is
every turn.

The second is delegation of the retry to an agent that did not make the original
call. In a `GroupChat` the manager selects who speaks next, and any selected
agent can re-issue the tool. That agent reads the same transcript but has no
private memory of having already committed the side effect — from its position
the earlier message is simply a prior attempt with an unclear outcome. So the
duplicate is issued by a participant that is structurally unable to know it is a
duplicate.

The consequence is the ordinary one and it is not recoverable by the agent: a
second charge, a second outbound message, a second delete against a resource that
no longer exists. The agent was granted the capability to act; without a key it
was granted the capability to act an unbounded number of times for one intent
(excessive agency, LLM06).

---

## Rule-by-rule defense

### AG2-015 — Mutating AutoGen tool has no idempotency key (Severity: medium, Confidence: 0.55, Fix type: code)

**What we detect:** a tool whose name starts with one of the mutating prefixes
and whose parameter list contains nothing matching `*idempot*`, `request_id`, or
`txn_id`.

**Why it is flaggable:** the signature is the contract. A mutating tool with no
key parameter cannot be told that a call is a repeat of an earlier one, so
nothing in the path — not the model, not the framework, not the backing service
— can distinguish a new intent from a re-attempt.

**Real-world consequence:**

- A `refund_payment(payment_id, amount)` call times out after the refund
  committed. The model reads the timeout as failure and calls again. The customer
  is refunded twice, and no later turn can undo it.
- In a five-agent chat, the manager selects a different speaker after an
  inconclusive `send_notification`. That agent re-sends. The recipient gets two
  messages, and the second agent had no way to know the first had landed.
- A `delete_record` retried after success fails the second time, and the model
  reads the failure as evidence the delete never worked — so it retries again, or
  reports the wrong outcome to the chat.

**Why severity is medium and not high:** the trigger requires a real retry, which
needs an inconclusive or lost response rather than merely a hostile input, and
many mutating tools front services that already deduplicate. The impact is also
bounded by what the tool can do — a duplicate write is damaging, not a privilege
escalation. It is not low because the damage is external and usually
irreversible: an agent cannot un-send a message or un-charge a card.

**Fix type — code:** adding the parameter and threading it to the backing API is
a source edit to the tool.

**Confidence 0.55 — the lowest in this pack, deliberately:** the rule reasons
from a name and a parameter list, and both are weak signals. False positives: a
tool named `update_cache` or `send_metric` is prefix-matching but harmless to
repeat; a tool fronting a service that deduplicates server-side on its own
natural key needs no parameter here; and a key threaded via a closure or a
context object rather than a parameter is invisible to the check. False
negatives: a mutating tool named `book_flight` or `transfer_funds` carries no
listed prefix and is never examined at all — the prefix list is a heuristic, not
a taxonomy of side effects.

---

## What this policy does not cover

- Mutating tools whose names fall outside the prefix list. `book_`, `transfer_`,
  `submit_`, `cancel_` and most domain verbs are not matched.
- Whether the key is actually *used*. A declared `idempotency_key` that the body
  ignores, or never forwards to the backing call, satisfies the rule completely.
- **Whether the key is stable.** This is the failure that matters most in
  practice: a key derived from a fresh `uuid4()` at call time is regenerated on
  the retry, so it deduplicates nothing while looking exactly like a fix.
- Whether the downstream service honors idempotency keys at all. The tool's half
  of the contract is worthless if the remote ignores it.
- Deduplication implemented outside the signature — a wrapper, a middleware, or a
  ledger the tool consults before acting.
- Non-tool side effects: an agent writing files or mutating shared state directly
  rather than through a registered tool.

---

## Recommendations beyond the fix

```python
def refund_payment(payment_id: str, amount: int, idempotency_key: str) -> dict:
    """Refund a payment. The key must be stable across retries of the same intent."""
    return billing.refund(payment_id, amount, idempotency_key=idempotency_key)


register_function(refund_payment, caller=assistant, executor=user_proxy,
                  description="Refund a payment. Reuse the same idempotency_key when retrying.")
```

1. Derive the key from the request's own identity — the payment id plus the
   intent, a hash of the arguments, a caller-supplied correlation id. Never a
   fresh `uuid4()` per call; that is the one shape that passes the rule and fixes
   nothing.
2. Say so in the tool description. The model chooses the argument, so "reuse the
   same `idempotency_key` when retrying" belongs where the model will read it —
   otherwise it invents a new one on the retry.
3. Confirm the backing service actually honors the key. Half a contract is no
   contract.
4. Return a result that distinguishes *did it* from *already done*, so a retry
   reports the truth instead of reading a deduplicated success as a fresh one.
5. In a `GroupChat`, assume the retry may come from a different agent than the
   original caller. The key has to travel in the transcript, not in one agent's
   private state — anything held outside the conversation is unavailable to
   whoever the manager selects next.
