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

# Policy Rationale: MCP Mutating-Tool Idempotency

**Policy ID:** `mcp_idempotency`  
**File:** `mcp/idempotency.yaml`  
**Rules:** MCP-007  
**References:** LLM06 (Excessive Agency)

> Shares the retry-safety threat model with
> [openai_sdk/idempotency.md](../openai_sdk/idempotency.md). MCP-specific angle
> only.

---

## What this policy covers

A mutating MCP tool — its name carries a side-effect prefix (`create_`, `send_`,
`delete_`, `post_`, `update_`, `refund_`, `charge_`, `issue_`) — that exposes no
idempotency-key parameter, detected by `all: [name_has_prefix: [...], not:
param_name_matches: {contains: [idempot], exact: [request_id, txn_id]}]`.

## Rule-by-rule defense

### MCP-007 — Mutating tool has no idempotency key (Severity: medium, Confidence: 0.55, Fix type: code)

**What we detect:** a side-effect-named handler with no parameter that looks like
an idempotency key.

**Why it is flaggable:** MCP clients retry tool calls under timeouts and ambiguous
failures, and the same model may be re-driven to repeat an action. Without an
idempotency key the handler executes the mutation twice — a duplicate charge,
order, or message. The excessive-agency framing (LLM06) is that the tool performs
an irreversible side effect with no replay guard. Medium severity, and confidence
0.55 because the signal is name-based: a tool named `create_*` may be internally
idempotent, and a mutating tool with a non-obvious name is missed. The finding is
a prompt to confirm, not a proof.

**Fix type — code:** accepting an idempotency key and de-duplicating server-side
is a source edit.

---

## What this policy does not cover

Whether the side effect is genuinely non-idempotent; mutating tools whose names
carry no recognized prefix; server-side de-duplication achieved without a visible
key parameter; and the TypeScript MCP surface (the name-prefix predicate runs on
Python handlers; a TS analogue is not wired in this pack).
