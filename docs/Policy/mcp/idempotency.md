---
policy_id: mcp_idempotency
category: mcp
topic: idempotency
rules:
  - id: MCP-007
    severity: medium
    confidence: 0.55
    scope: tool
    fix_type: code
references: [LLM06]
---

# Policy Rationale: MCP mutating-tool idempotency

**Policy ID:** `mcp_idempotency`  
**File:** `mcp/idempotency.yaml`  
**Rules:** MCP-007  
**Severities:** medium  
**Fix types:** code  
**References:** LLM06

---

## What this policy covers

MCP tools — functions registered on an MCP server via `@server.tool` /
`@mcp.tool` / `.register_tool` — whose name signals a mutating, side-effecting
action (`create_`, `send_`, `delete_`, `post_`, `update_`, `refund_`,
`charge_`, `issue_`, via `name_has_prefix`) but whose parameters carry no
idempotency key. The negative half of the match is `not param_name_matches`
with `contains: [idempot]` and `exact: [request_id, txn_id]`, so a tool is
flagged only when none of its parameter names contain `idempot`
(`idempotency_key`, `idempotency-key`, …) and none is exactly `request_id` or
`txn_id`. In short: the tool changes the world but exposes no parameter the
caller can use to mark a retry as a duplicate. This is a name-and-parameter
heuristic over the discovered MCP tool signature, not a dataflow check.

---

## Why idempotency is a distinct concern in agent tools

MCP servers are driven by orchestrators, not by hand, and orchestrators retry.
A tool call that times out, fails its transport, or returns an ambiguous error
is routinely re-sent — sometimes by the host's retry policy on the JSON-RPC
call, sometimes by the model's own reasoning when it does not see a result.
For a read that is harmless. For a *mutating* MCP tool it is not: a
`send_email`, `create_order`, or `charge_card` retried after the side effect
already executed but the acknowledgement was lost in transit fires the side
effect a second time. The canonical mechanism is the timeout double-spend: the
charge succeeds, the response is lost on the wire, the orchestrator retries the
identical tool call, and without an idempotency key the handler has no way to
recognize the retry — so the customer is billed twice. No human confirms the
retry; it happens inside the orchestration loop.

This is worse for MCP than for an SDK-local tool for a structural reason: an
MCP server is a shared backend. The same server, exposing the same mutating
tool, can be driven by *multiple* agents and multiple host sessions
concurrently — each with its own retry behavior and none aware of the others'
in-flight calls. The tool author controls the server but not the callers, so
"just don't retry" is not an option the author can enforce. Without an
idempotency key the server cannot tell "agent B is asking for a second,
distinct charge" apart from "agent A's host is retrying the same charge whose
result it did not see." An idempotency key is the only thing that lets the
server collapse a retried call onto the original action and return the original
result, regardless of which caller or which retry layer re-sent it.

This maps to OWASP LLM06 (Excessive Agency): the agent can cause real-world
effects through the tool, and without server-side deduplication those effects
compound — duplicate charges, duplicate orders, duplicate messages — beyond
what any single user intended.

---

## Rule-by-rule defense

### MCP-007 — Mutating tool has no idempotency key (Severity: medium, Confidence: 0.55, Fix type: code)

**What we detect:**  
An MCP tool whose registered name begins with one of the mutating verb prefixes
`create_`, `send_`, `delete_`, `post_`, `update_`, `refund_`, `charge_`, or
`issue_` (`name_has_prefix`), AND whose parameter names contain no
idempotency-key-shaped name — the match fires only when `not param_name_matches`
holds for `contains: [idempot]` and `exact: [request_id, txn_id]`. So
`charge_card(token, cents)` fires; `charge_card(token, cents,
idempotency_key)` does not, and neither does a tool that takes a `request_id`
or `txn_id` parameter. A reader can reconstruct the YAML `match.all` block from
this: one `name_has_prefix` clause over the eight verbs, one negated
`param_name_matches` clause over the `idempot` substring plus the two exact
spellings.

**Why it is flaggable:**  
A mutating tool with no dedupe parameter cannot distinguish a retry from a new
request. Because the parameter set is the only channel an MCP caller has to
signal "this is the same logical action as before," its absence means a
retried call — from the host's retry policy or the model re-issuing the call —
double-fires the side effect server-side. The mutating-verb prefix is the
signal that the body performs a write whose duplication is user-visible.

**Real-world consequence:**  
- `charge_card(token, cents)` retried after a lost response bills the customer
  twice — the timeout double-spend.
- `send_email(to, body)` retried sends the message twice; `create_order(...)`
  retried places two orders; `refund_payment(...)` retried issues two refunds.

**Why severity is medium and not high:**  
The damage is real and user-visible (a duplicate charge, order, or message),
which keeps it above low. It is not high because the harm is conditional: it
requires a retry to actually occur *and* the downstream backend to not already
dedupe by some other means (many payment and messaging APIs enforce
idempotency server-side regardless of the tool signature, or dedupe on a
natural key). The rule flags the missing safeguard at the tool boundary, not a
guaranteed double-execution — so it warrants attention, not an emergency.

**Fix type — code:**  
Closing the gap means adding an idempotency-key parameter to the tool and
threading it through to the backend call — an edit to the tool's own source.
It cannot be supplied by a guardrail, hook, or sandbox policy outside the tool,
so this is `code`, not `config`.

**Confidence 0.55:**  
This is the lowest-confidence rule in the MCP pack by design (0.55 < 0.80) —
it is a name-and-parameter heuristic with no view of the tool body or the
backend. **False positives:** a `create_`-prefixed tool that is naturally
idempotent or non-mutating (`create_summary` returns generated text and writes
nothing; `create_session_token` may be safe to repeat) is flagged despite being
harmless; a tool whose backend enforces idempotency server-side (a Stripe-style
API that honors a key the tool never names, or that dedupes on a natural order
number) is safe despite the empty signature; and an idempotency key passed
under a non-standard name outside the heuristic — `dedupe_key`, `client_token`,
`correlation_id`, the camelCase `requestId`/`idempotencyKey` — is not matched
by `contains:[idempot]` or `exact:[request_id, txn_id]`, so the tool is flagged
even though it is safe. **False negatives:** a genuinely-mutating tool named
outside the eight-verb prefix set (`book_table`, `apply_patch`, `pay_invoice`,
`transfer_funds`, `cancel_order`) is missed entirely, because the rule keys off
the verb prefix and these do not start with one. Both error modes share one
root cause: a name heuristic that sees the parameter *names* but not how the
parameter is used or what the body does. Treat every hit as a review prompt for
a side-effecting MCP tool, not a confirmed defect.

---

## What this policy does not cover

Written adversarially — these are the ways a developer could correctly argue a
finding is wrong, or point to an unsafe tool the rule misses:

- **Backend-enforced idempotency.** A tool calling an API that dedupes by
  natural key or its own idempotency mechanism is safe despite no key in the
  MCP signature. The rule sees the signature, not the backend — a guaranteed
  false positive whenever the safeguard lives downstream.
- **Mutating tools named outside the verb set.** `book_table`, `apply_patch`,
  `pay_invoice`, `transfer_funds`, `cancel_subscription`, `archive_record` all
  mutate but begin with no recognized prefix, so they are never flagged — a
  false negative on genuinely-unsafe tools.
- **Idempotency keys spelled outside the heuristic.** A tool that *does* take a
  dedupe parameter named `dedupe_key`, `client_token`, `correlation_id`, or the
  camelCase `requestId` / `idempotencyKey` is flagged anyway, because the
  negative match only recognizes the `idempot` substring and the exact
  `request_id` / `txn_id` spellings.
- **Whether a present key is actually honored.** Even when the tool exposes an
  `idempotency_key` parameter and the rule stays silent, the rule never checks
  that the key is threaded to the backend, persisted, and used to return the
  original result on a repeat. A tool can accept the parameter and still
  double-fire if it ignores it.
- **Non-retry duplication.** The model (or a second agent) deliberately calling
  the tool twice for two distinct logical actions is not a retry and is out of
  scope — and is exactly what an idempotency key is *meant* to allow through.
- **Naturally-idempotent mutations.** A `create_`/`update_`/`post_` tool whose
  effect is a safe upsert (writing the same resource twice produces the same
  state) is flagged but carries no real duplicate-effect risk.

---

## Recommendations beyond the fix

```python
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("payments")


@mcp.tool()
def charge_card(token: str, cents: int, idempotency_key: str) -> dict:
    """Charge a card. The caller MUST pass a stable idempotency_key per logical
    charge so an orchestrator retry of the same charge is collapsed by the
    provider rather than billed twice; use a fresh key only for a genuinely new
    charge."""
    charge = gateway.charge(token, cents, idempotency_key=idempotency_key)
    return {"ok": True, "charge_id": charge.id}
```

1. **Require the idempotency key as a parameter** and document, in the tool
   description the model reads, that it must reuse the *same* key when retrying
   the same logical action and supply a fresh key only for a genuinely new one.
2. **Honor the key end-to-end, not just at the signature.** Persist it
   server-side and return the original result on a repeated key, rather than
   merely accepting the parameter — the rule checks presence, but only
   end-to-end deduplication prevents the double-spend.
3. **Prefer a natural idempotency key where one exists** (an order number, a
   message id, an invoice id) over a synthetic one, so the dedupe survives even
   a caller that forgets to thread the synthetic key.
4. **Dedupe at the MCP server, not per-agent.** Because the same server can be
   driven by multiple agents and sessions, keep the idempotency store on the
   server (shared) so concurrent callers collapse onto the same record instead
   of each holding their own.
5. **Make retries safe by default at the boundary**: wrap mutating handlers so
   an unrecognized-but-required key is rejected loudly rather than silently
   processed without deduplication.
