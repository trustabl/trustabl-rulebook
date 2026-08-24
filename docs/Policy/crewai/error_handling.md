---
policy_id: crewai_error_handling
category: crewai
topic: error_handling
rules:
  - id: CREW-007
    severity: low
    confidence: 0.6
    scope: tool
    fix_type: code
references: [LLM05]
---

# Policy Rationale: CrewAI Error Contract Hygiene

**Policy ID:** `crewai_error_handling`  
**File:** `crewai/error_handling.yaml`  
**Rules:** CREW-007  
**Severities:** low  
**Fix types:** code  
**References:** LLM05 (Improper Output Handling)

> Shares the structured-error threat model with
> [openai_sdk/error_handling.md](../openai_sdk/error_handling.md). CrewAI-specific
> angle only.

---

## What this policy covers

A CrewAI tool — a `@tool`-decorated function or a `BaseTool` `_run` body — that
contains a `raise` and no `try`/`except`, detected by
`all: [has_raise: true, has_try_except: false]`.

---

## Why error handling is a distinct concern in agent tools

CrewAI's executor catches a tool exception and returns its text into the agent's
scratchpad as the observation for that step. The model then reasons over a
sentence, not a status. It cannot separate "the argument was wrong" from "the
remote timed out" from "you lack permission", and its default recovery for an
undifferentiated failure is to repeat the call. Because CrewAI bounds an agent by
`max_iter` rather than by any notion of progress, that repetition consumes the
entire budget: the agent retries an unfixable call until the limit stops it, and
the task ends with no result and a full bill.

Delegation is what makes CrewAI's version of this worse than the single-agent
case. A crew's agents pass work to each other, and a delegating agent reads the
delegate's output as its own observation. An opaque error does not stay local to
the task that produced it — it becomes the text a second agent reasons over, and
that agent has strictly less context for interpreting it than the first. A
`KeyError: 'ACME-2231'` that at least sat next to the failing call in agent A's
scratchpad reaches agent B as a bare string with no call site attached. Failures
therefore degrade as they propagate through the crew rather than being handled at
the boundary where the information existed.

The stringified exception is also a disclosure channel. `str(e)` from a database
or filesystem error carries paths, hostnames and connection strings, and in a
crew that text is copied into every downstream agent's context and into the run
transcript (improper output handling, LLM05).

---

## Rule-by-rule defense

### CREW-007 — CrewAI tool raises exceptions without a structured error contract (Severity: low, Confidence: 0.6, Fix type: code)

**What we detect:**  
A tool function body containing at least one `raise` statement and no
`try`/`except` block anywhere in that body.

**Why it is flaggable:**  
Every failure the function can produce leaves it as an exception, so the
observation the executor writes into the scratchpad is a stringified traceback.
The tool exposes no field the model — or a delegating agent — can branch on.

**Real-world consequence:**

- A `fetch_invoice` tool raises `KeyError` on an unknown id. The researcher agent
  sees `KeyError: 'INV-88213'`, cannot tell the id was wrong rather than the
  service broken, and re-issues the identical call until `max_iter` ends the task.
- A delegated `lookup_vendor` raises a `requests.ConnectionError`. The delegating
  agent receives the connection string embedded in the message as its observation
  and incorporates it into its own summary.
- A tool raising on a transient timeout gives the model no `retryable` signal, so
  a failure that a single retry would have cleared is reported to the crew as a
  hard failure.

**Why severity is low and not medium:**  
The impact is degraded recovery plus an incidental disclosure channel; it grants
no capability and crosses no privilege boundary. A raise is also often deliberate,
with a wrapping frame or a `BaseTool` subclass expected to structure it. Low
matches the severity of the equivalent rules in the Claude, OpenAI, ADK and MCP
packs.

**Fix type — code:**  
Returning `{"error": ..., "retryable": ...}` instead of raising is a source edit
to the tool body.

**Confidence 0.6:**  
The check is body-local. False positives: a tool that raises because a decorator
or a `BaseTool` wrapper converts the exception into the structured shape the rule
asks for. False negatives: a `try`/`except` that catches and re-raises, or that
returns a bare string, satisfies the predicate while providing no contract. 0.6
reflects a single-frame syntactic check standing in for a whole-call-path
property.

---

## What this policy does not cover

- Exception handling by a wrapping frame — a decorator, a `BaseTool` subclass, or
  a crew-level error handler — outside the tool body.
- A `try`/`except` that catches and re-raises, or returns an unstructured string.
- Whether the structured error is correct: that `retryable` reflects reality, or
  that the message names what the model should change.
- Whether the message actually contains sensitive data.
- How a delegating agent interprets a well-formed structured error; the rule
  checks that one exists, not that the crew uses it well.

---

## Recommendations beyond the fix

```python
from crewai.tools import tool


@tool("fetch_invoice")
def fetch_invoice(invoice_id: str) -> dict:
    """Fetch an invoice by id."""
    try:
        return {"ok": True, "invoice": INVOICES[invoice_id]}
    except KeyError:
        return {"ok": False, "error": "no invoice with that id", "retryable": False}
    except TimeoutError:
        return {"ok": False, "error": "billing service timed out", "retryable": True}
```

1. Return a `retryable` field on every failure path. Without it an agent spends its
   whole `max_iter` budget re-issuing a call that cannot succeed.
2. Write the error for the *next* reader, not the current one. In a crew the string
   is also read by a delegating agent that never saw the call site, so it must name
   the tool and the offending input itself.
3. Keep failures local: handle them in the tool that produced them rather than
   letting an opaque string propagate through delegation, where each hop loses
   context.
4. Never pass a raw `str(e)` from a database or filesystem client through; in a crew
   it is copied into every downstream agent's context.
