---
policy_id: langchain_observability
category: langchain
topic: observability
rules:
  - id: LC-020
    severity: low
    confidence: 0.65
    scope: tool
    fix_type: code
references: []
---

# Policy Rationale: LangChain Tool Observability Hygiene

**Policy ID:** `langchain_observability`  
**File:** `langchain/observability.yaml`  
**Rules:** LC-020  
**Severities:** low  
**Fix types:** code  
**References:** none

---

## What this policy covers

How a LangChain tool emits diagnostics. The policy has one rule, LC-020, which
applies to Python LangChain tools (`applies_to: langchain_tool`,
`language: python`, `scope: tool`) and matches a tool whose body contains a
print call (`has_print_call: true`). The pack's policy description says a tool
body that prints to stdout writes outside the callback system the rest of the
run is recorded through.

---

## Why stdout diagnostics are a distinct concern in LangChain tools

A `print()` in a LangChain tool writes to the process's stdout. The pack's
explanation makes three points about where that output goes.

- **Stdout.** The pack's explanation says the return value
  is what flows back into the executor loop, and that the output silently
  disappears in any deployment that captures structured records rather than raw
  stdout.
- **Callback system.** `BaseTool.run` reports a tool's start,
  end, and error to the run's callback handlers (`on_tool_start`,
  `on_tool_end`, `on_tool_error`). The pack's explanation says LangChain passes
  these to LangSmith or whatever tracer is configured, and that a bare print is
  detached from the run and the step that produced it, so when someone debugs
  from a trace rather than a terminal it is not there.
- **MCP stdio transport.** The pack's explanation
  says that if the same tool is served over an MCP stdio transport, the loose
  print frames interleave with JSON-RPC messages and corrupt the stream.

---

## Rule-by-rule defense

### LC-020 — LangChain tool prints to stdout for diagnostics (Severity: low, Confidence: 0.65, Fix type: code)

**What we detect:**  
A Python LangChain tool whose body calls `print()`, matched by the predicate
`has_print_call: true`.

**Why it is flaggable:**  
The call writes to the process's stdout. The mechanism is the one stated
[above](#why-stdout-diagnostics-are-a-distinct-concern-in-langchain-tools): the
output is outside the callback system, and the pack's explanation says it is
detached from the run and the step that produced it.

**Real-world consequence:**  
- If a tool prints a debug line and a failing run is later debugged from its
  trace, the pack's explanation says the line is not in the trace.
- If the tool is also served over an MCP stdio transport, the pack's
  explanation says the print frames interleave with the JSON-RPC messages and
  corrupt the stream.

**Why severity is low:**  
The pack sets low and states no reasoning for it. The costs the explanation
names are output that is missing from the trace and, over an MCP stdio
transport, a corrupted stream.

**Fix type — code:**  
The pack's fix is an edit to the tool source: remove the `print()`, emit
operator diagnostics through a module logger
(`logging.getLogger(__name__).info(...)`) so they land in the application's log
sink, or attach the detail to the run through the callback system so it is
correlated with the step that produced it. If the information needs to reach
the model, return it as part of the tool's result.

**Confidence 0.65:**  
The pack sets 0.65 for this rule and names no false-positive or false-negative
scenarios for it.

---

## What this policy does not cover

- **Code outside a tool body.** LC-020 is tool-scoped (`scope: tool`).
- **Languages other than Python.** The rule is declared for
  `language: python`.
- **The deployment.** The match is the print call alone. Whether stdout is
  captured, or whether the tool is served over an MCP stdio transport, is not
  part of the match.
- **What the print contains.** The pack does not address the content of the
  printed output, so this document attaches no OWASP reference.
- **Project-level instrumentation.** Whether the project wires observability at
  all is LC-202, and whether an agent has no callbacks while the rest of the
  project is instrumented is LC-112, both in [tracing.md](tracing.md).

---

## Recommendations beyond the fix

```python
import logging
from typing import Any

from langchain_core.callbacks import dispatch_custom_event
from langchain_core.tools import tool

logger = logging.getLogger(__name__)

ORDERS: dict[str, dict[str, Any]] = {}


@tool
def lookup_order(order_id: str) -> str:
    """Look up an order by its ID, e.g. "ord_1042", and return a one-line summary of it."""
    order = ORDERS.get(order_id)
    # Operator diagnostics: a module logger, not print().
    logger.info("lookup_order order_id=%s found=%s", order_id, order is not None)
    # Or attach the detail to the run through the callback system.
    dispatch_custom_event("lookup_order", {"order_id": order_id, "found": order is not None})
    # Model-facing information: the return value.
    if order is None:
        return f"No order {order_id}."
    return str(order)
```

1. **Use a module logger.** `logging.getLogger(__name__).info(...)` sends the
   record to the application's log sink.
2. **Attach the detail to the run.** Emit it through the callback system, as
   the example does, so it is correlated with the step that produced it.
3. **Put model-facing information in the return value.** If the information
   needs to reach the model, return it as part of the tool's result.
