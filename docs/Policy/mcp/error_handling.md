---
policy_id: mcp_error_handling
category: mcp
topic: error_handling
rules:
  - id: MCP-006
    severity: low
    confidence: 0.6
    scope: tool
    fix_type: code
references: [LLM05]
---

# Policy Rationale: MCP Error Contract Hygiene

**Policy ID:** `mcp_error_handling`  
**File:** `mcp/error_handling.yaml`  
**Rules:** MCP-006  
**References:** LLM05 (Improper Output Handling)

> Shares the structured-error threat model with
> [openai_sdk/error_handling.md](../openai_sdk/error_handling.md). MCP-specific
> angle only.

---

## What this policy covers

An MCP tool handler that can raise without catching, detected by
`all: [has_raise: true, has_try_except: false]`.

## Rule-by-rule defense

### MCP-006 — Tool raises exceptions without a structured error contract (Severity: low, Confidence: 0.6, Fix type: code)

**What we detect:** a handler body that contains a `raise` and no `try`/`except`.

**Why it is flaggable:** when an MCP tool handler raises, the runtime surfaces the
exception to the connecting client as an opaque protocol error. The model on the
other end often cannot recover or retry intelligently, and the raw message may
leak internal detail — stack frames, absolute paths, secrets in arguments —
across the server's trust boundary to whatever client connected (improper output
handling, LLM05). Low severity because the impact is degraded recovery plus a
modest disclosure channel, and a handler often raises intentionally for a caller
or runtime that structures it; confidence 0.6 because the body-only check does
not see a `try` in a calling frame.

**Fix type — code:** returning a structured `{"error": ..., "retryable": ...}`
result instead of raising is a source edit.

---

## What this policy does not cover

Whether the raised message actually contains sensitive data; exception handling
done by a wrapping frame outside the handler body; and the TypeScript MCP error
surface (no TS raise/catch predicate is wired).
