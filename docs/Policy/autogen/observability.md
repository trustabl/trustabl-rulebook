---
policy_id: autogen_observability
category: autogen
topic: observability
rules:
  - id: AG2-018
    severity: low
    confidence: 0.65
    scope: tool
    fix_type: code
references: []
---

# Policy Rationale: AutoGen Tool Observability Hygiene

**Policy ID:** `autogen_observability`  
**File:** `autogen/observability.yaml`  
**Rules:** AG2-018  
**Severities:** low  
**Fix types:** code  
**References:** none

---

## What this policy covers

How a registered AutoGen tool emits diagnostics. The policy has one rule,
AG2-018, which applies to Python AutoGen / AG2 tools (`applies_to: autogen_tool`,
`language: python`, `scope: tool`) and matches a tool whose body contains a
print call (`has_print_call: true`). A tool body that prints writes to the
process's stdout, where AutoGen's default console output also narrates the
conversation, so the record is neither visible to the agents nor separable
from the transcript around it.

---

## Why stdout diagnostics are a distinct concern in AutoGen tools

A `print()` in a registered AutoGen tool reaches neither agent and is hard to
recover afterwards.

- **Neither agent sees it.** Only the return value is posted back into the
  conversation as the executor's reply. In any deployment that captures
  structured records rather than raw stdout, the output silently disappears.
- **It reads as part of the exchange.** With AutoGen's default console output,
  the conversation itself is narrated to stdout, so a tool print lands in the
  middle of the transcript and reads as though it were part of the exchange,
  when it is invisible to the agents reasoning over it.
- **It carries no marker.** The printed line does not say which round or which
  tool call produced it. A log sink that captures structured records rather
  than raw stdout loses it.

---

## Rule-by-rule defense

### AG2-018 — AutoGen tool prints to stdout for diagnostics (Severity: low, Confidence: 0.65, Fix type: code)

**What we detect:**  
A Python AutoGen tool whose body calls `print()`, matched by the predicate
`has_print_call: true`.

**Why it is flaggable:**  
The call writes to the process's stdout. Only the return value is posted back
into the conversation as the executor's reply, so neither agent sees the
output, and the line carries no marker for which round or which tool call
produced it.

**Real-world consequence:**  
- The tool prints a debug line during a terminal run. The line appears between
  the narrated messages and reads as part of the exchange, but the assistant
  never received it.
- The run is later reconstructed from a log sink that captures structured
  records rather than raw stdout. The line is missing.

**Why severity is low:**  
The pack sets low and states no reasoning for it.

**Fix type — code:**  
The pack's fix is an edit to the tool source: remove the `print()`, emit
operator diagnostics through a module logger
(`logging.getLogger(__name__).info(...)`) so the record carries its own module
and level and lands in the application's log sink rather than the
conversation narration, and return anything the assistant needs as part of
the tool's result.

**Confidence 0.65:**  
The pack sets 0.65 for this rule and names no false-positive or false-negative
scenarios for it.

---

## What this policy does not cover

- **Code outside a tool body.** AG2-018 is tool-scoped (`scope: tool`).
- **Languages other than Python.** The rule is declared for `language: python`
  only.
- **The deployment.** The match is the print call alone. Whether stdout is
  captured, or where the conversation is narrated, is not part of the match.
- **What the print contains.** The pack does not address the content of the
  printed output, so this document attaches no OWASP reference.
- **Project-level instrumentation.** Whether the project wires observability
  at all is AG2-202, in [tracing.md](tracing.md).

---

## Recommendations beyond the fix

```python
import logging

from autogen import register_function

logger = logging.getLogger(__name__)

ORDERS: dict[str, dict] = {}


def lookup_order(order_id: str) -> str:
    """Look up an order by its ID, e.g. "ord_1042", and return a one-line summary of it."""
    order = ORDERS.get(order_id)
    # Operator diagnostics: a module logger, never print().
    logger.info("lookup_order order_id=%s found=%s", order_id, order is not None)
    # Assistant-facing information: the return value.
    if order is None:
        return f"No order {order_id}."
    return str(order)


register_function(
    lookup_order, caller=assistant, executor=executor,
    description="Look up an order by its ID and return a one-line summary of it.",
)
```

1. **Use a module logger.** `logging.getLogger(__name__).info(...)` gives the
   record its own module and level and sends it to the application's log sink
   rather than the conversation narration.
2. **Put assistant-facing information in the return value.** If the
   information needs to reach the assistant, return it as part of the tool's
   result.
