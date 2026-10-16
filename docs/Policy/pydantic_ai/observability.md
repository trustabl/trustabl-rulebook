---
policy_id: pydantic_ai_observability
category: pydantic_ai
topic: observability
rules:
  - id: PYD-012
    severity: low
    confidence: 0.65
    scope: tool
    fix_type: code
references: []
---

# Policy Rationale: Pydantic AI Tool Observability Hygiene

**Policy ID:** `pydantic_ai_observability`  
**File:** `pydantic_ai/observability.yaml`  
**Rules:** PYD-012  
**Severities:** low  
**Fix types:** code  
**References:** none

---

## What this policy covers

How a Pydantic AI tool emits diagnostics. The policy has one rule, PYD-012,
which applies to Python Pydantic AI tools (`applies_to: pydantic_ai_tool`,
`language: python`, `scope: tool`) and matches a tool whose body contains a
print call (`has_print_call: true`). A tool body that prints to stdout writes
outside the SDK's instrumentation, and the model never sees what it prints.

---

## Why stdout diagnostics are a distinct concern in Pydantic AI tools

A `print()` in a Pydantic AI tool reaches none of the consumers that matter.

- **The model never sees it.** Only the return value flows back into the agent
  run. In any deployment that captures structured records rather than raw
  stdout, the output silently disappears for the operator as well.
- **It lands outside the SDK's instrumentation.** The print is not attached to
  the run that produced it. The pack's alternative, attaching the detail to the
  current span through Logfire or the OpenTelemetry API, is what correlates it
  with that run.
- **An MCP stdio transport carries JSON-RPC on stdout.** If the tool is ever
  also served over an MCP stdio transport, the loose print frames interleave
  with JSON-RPC messages and corrupt the stream.

---

## Rule-by-rule defense

### PYD-012 — Pydantic AI tool prints to stdout for diagnostics (Severity: low, Confidence: 0.65, Fix type: code)

**What we detect:**  
A Python Pydantic AI tool whose body calls `print()`, matched by the predicate
`has_print_call: true`.

**Why it is flaggable:**  
The call writes to the process's stdout. Only the return value flows back into
the agent run, and the print is outside the SDK's instrumentation, so the model
never sees it and it is not attached to the run that produced it.

**Real-world consequence:**  
- The tool prints a debug line in a deployment that captures structured
  records rather than raw stdout. The line silently disappears.
- The tool is also served over an MCP stdio transport. The print interleaves
  with the JSON-RPC messages on stdout and corrupts the stream.

**Why severity is low:**  
The pack sets low and states no reasoning for it.

**Fix type — code:**  
The pack's fix is an edit to the tool source: remove the `print()`, emit
operator diagnostics through a module logger
(`logging.getLogger(__name__).info(...)`) or attach the detail to the current
span through Logfire or the OpenTelemetry API, and return anything the model
needs as part of the tool's result.

**Confidence 0.65:**  
The pack sets 0.65 for this rule. It states no false positives, false
negatives, or other limits for PYD-012.

---

## What this policy does not cover

- **Code outside a tool body.** PYD-012 is tool-scoped (`scope: tool`).
- **Languages other than Python.** The rule is declared for `language: python`
  only.
- **The deployment.** The match is the print call alone. Whether stdout is
  captured, or whether the tool is served over an MCP stdio transport, is not
  part of the match.
- **What the print contains.** The pack does not address the content of the
  printed output, so this document attaches no OWASP reference.
- **Project-level instrumentation.** Whether the project wires observability at
  all is PYD-202, and whether an individual `Agent(...)` is left uninstrumented
  is PYD-107, both in [tracing.md](tracing.md).

---

## Recommendations beyond the fix

```python
import logging

from opentelemetry import trace
from pydantic_ai import Agent

logger = logging.getLogger(__name__)

agent = Agent("openai:gpt-4o")

ORDERS: dict[str, dict] = {}


@agent.tool_plain
def lookup_order(order_id: str) -> str:
    """Look up an order by its ID and return a one-line summary of it.

    Args:
        order_id: The order's ID, e.g. "ord_1042".
    """
    order = ORDERS.get(order_id)
    # Operator diagnostics: a module logger, never print().
    logger.info("lookup_order order_id=%s found=%s", order_id, order is not None)
    # Or attach the detail to the current span, correlated with the run.
    trace.get_current_span().add_event(
        "lookup_order", {"order_id": order_id, "found": order is not None}
    )
    # Model-facing information: the return value.
    if order is None:
        return f"No order {order_id}."
    return str(order)
```

1. **Use a module logger.** `logging.getLogger(__name__).info(...)` gives the
   record a module and a level.
2. **Attach the detail to the current span.** Through Logfire or the
   OpenTelemetry API, so it is correlated with the run that produced it.
3. **Put model-facing information in the return value.** If the information
   needs to reach the model, return it as part of the tool's result.
