---
policy_id: pydantic_ai_error_handling
category: pydantic_ai
topic: error_handling
rules:
  - id: PYD-008
    severity: low
    confidence: 0.6
    scope: tool
    fix_type: code
references: [LLM05]
---

# Policy Rationale: Pydantic AI Error Contract Hygiene

**Policy ID:** `pydantic_ai_error_handling`  
**File:** `pydantic_ai/error_handling.yaml`  
**Rules:** PYD-008  
**Severities:** low  
**Fix types:** code  
**References:** LLM05 (Improper Output Handling)

> Shares the structured-error threat model with
> [openai_sdk/error_handling.md](../openai_sdk/error_handling.md). Pydantic
> AI-specific angle only.

---

## What this policy covers

A Pydantic AI tool — a function registered with `@agent.tool` or
`@agent.tool_plain`, or passed via `tools=` — whose body contains a `raise` and
no `try`/`except`, detected by
`all: [has_raise: true, has_try_except: false]`.

---

## Why error handling is a distinct concern in agent tools

Pydantic AI is the framework in this set that already has the right answer built
in, which is what makes an uncaught raise here a sharper defect than elsewhere.

The framework recognizes two kinds of tool failure and routes them differently.
`ModelRetry` is the recoverable channel: the framework catches it, feeds the
message back to the model as guidance, and lets it call the tool again with
corrected arguments, bounded by the tool's `retries` setting. Every *other*
exception is the unrecoverable channel: it propagates out of `agent.run()` and
ends the run. The two paths are not a convention — they are the framework's
control flow.

A tool that lets whatever the underlying library raised escape is therefore not
merely failing to add structure; it is routing failures into the wrong channel.
A `ValidationError` on a malformed argument, a `KeyError` on a bad id, a 404 from
an HTTP client — all are precisely the failures the model could correct on a
second attempt, and all of them take the terminating path because the tool never
translated them. The retry mechanism the framework provides sits unused while the
run aborts. The caller sees an exception from `agent.run()` and cannot tell a
genuine outage from an argument the model chose badly.

The ordinary disclosure concern applies as well: whether the exception ends the
run or is surfaced to the model, `str(e)` from a database or filesystem error
carries paths, hostnames and connection strings across a boundary they were not
meant to cross (improper output handling, LLM05).

---

## Rule-by-rule defense

### PYD-008 — Pydantic AI tool raises exceptions without a structured error contract (Severity: low, Confidence: 0.6, Fix type: code)

**What we detect:**  
A tool function body containing at least one `raise` statement and no
`try`/`except` block anywhere in that body.

**Why it is flaggable:**  
Without a local handler, the tool cannot be choosing between the framework's two
error channels — every failure it produces takes whichever path the underlying
library's exception type happens to imply, which for anything other than a
deliberate `ModelRetry` is the run-terminating one.

**Real-world consequence:**

- A `get_account` tool raises `KeyError` for an unknown id. Rather than the model
  being told the id was wrong and retrying with a correct one, `agent.run()`
  raises and the run ends. The recoverable failure was routed as fatal.
- A tool calling `httpx` lets `HTTPStatusError` escape on a 404. The run aborts on
  a condition a `ModelRetry("no record with that id; check the identifier")` would
  have resolved in one extra turn.
- A tool raising `OperationalError` from a database client propagates the DSN —
  host, port, user — out through the exception to whatever logs the failed run.

**Why severity is low and not medium:**  
The impact is degraded recovery plus an incidental disclosure channel; it grants
no capability and crosses no privilege boundary. A raise may also be entirely
deliberate — a `ModelRetry` is itself a `raise`, and a tool that raises it with no
surrounding `try` is doing exactly the right thing while still matching this
predicate. Low matches the equivalent rules in the Claude, OpenAI, ADK and MCP
packs.

**Fix type — code:**  
Catching the failure and either raising `ModelRetry` with corrective guidance or
returning `{"error": ..., "retryable": ...}` is a source edit to the tool body.

**Confidence 0.6:**  
The check is body-local and type-blind, which produces error in both directions.
The notable false positive is specific to this framework: a tool that raises
`ModelRetry` directly, with no `try`/`except`, is already using the recoverable
channel correctly and will still match — the predicate sees a `raise`, not which
exception. False negatives: a `try`/`except` that catches and re-raises, or that
returns a bare string, satisfies the predicate without providing a contract. 0.6
reflects a single-frame syntactic check standing in for a whole-call-path
property.

---

## What this policy does not cover

- Which exception type is raised. A bare `raise ModelRetry(...)` — correct usage
  — matches this rule, because the predicate is type-blind.
- Exception handling by a wrapping frame outside the tool body.
- A `try`/`except` that catches and re-raises, or returns an unstructured string.
- Whether the tool's `retries` setting is configured sensibly, or whether a
  `ModelRetry` message actually tells the model what to change.
- Whether the message contains sensitive data.
- Output validators and `@agent.output_validator`, which have their own retry
  path and are not tool bodies.

---

## Recommendations beyond the fix

```python
from pydantic_ai import Agent, ModelRetry

agent = Agent("openai:gpt-4o")


@agent.tool_plain(retries=2)
def get_account(account_id: str) -> dict:
    """Get an account by id."""
    try:
        return {"account": ACCOUNTS[account_id]}
    except KeyError:
        # Recoverable: hand the model something it can act on.
        raise ModelRetry(f"no account {account_id!r}; ids look like ACC-12345")
    except TimeoutError:
        return {"error": "account service timed out", "retryable": True}
```

1. Decide, per failure, which of the framework's two channels it belongs in.
   `ModelRetry` for anything the model could fix by calling differently; a
   propagating exception only for states no retry resolves.
2. Write the `ModelRetry` message as an instruction, not a diagnosis. "ids look like
   ACC-12345" changes the next call; "KeyError" does not.
3. Set `retries` on the tool to bound the corrective loop, so a model that cannot
   find a valid argument fails cleanly rather than retrying indefinitely.
4. Never let a client library's exception escape untranslated — besides ending the
   run, `str(e)` from a database client carries the DSN out with it.
