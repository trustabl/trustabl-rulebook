---
policy_id: crewai_observability
category: crewai
topic: observability
rules:
  - id: CREW-012
    severity: low
    confidence: 0.65
    scope: tool
    fix_type: code
references: []
---

# Policy Rationale: CrewAI Tool Observability Hygiene

**Policy ID:** `crewai_observability`  
**File:** `crewai/observability.yaml`  
**Rules:** CREW-012  
**Severities:** low  
**Fix types:** code  
**References:** none

---

## What this policy covers

How a CrewAI tool emits diagnostics. The policy has one rule, CREW-012, which
applies to Python CrewAI tools (`applies_to: crewai_tool`,
`language: python`, `scope: tool`) and matches a tool whose body contains a
print call (`has_print_call: true`). A tool body that prints to stdout writes
into the same channel as the crew's own verbose narration, so the record is
neither visible to the agent nor separable from the run commentary around
it.

---

## Why stdout diagnostics are a distinct concern in CrewAI tools

A `print()` in a CrewAI tool reaches neither the agent nor a structured log.

- **The agent never sees it.** Only the return value becomes the observation
  the agent reasons over. In any deployment that captures structured records
  rather than raw stdout, the output silently disappears.
- **It lands in the crew's narration.** A crew running with `verbose=True`
  writes its own narration to the same stream, so a tool print is
  interleaved into the run commentary of the crew's agents.
- **It carries no marker.** Nothing in the printed line says which agent,
  task or tool call emitted it. What looks like working diagnostics in a
  terminal is unattributable the moment the crew runs anywhere else.

---

## Rule-by-rule defense

### CREW-012 — CrewAI tool prints to stdout for diagnostics (Severity: low, Confidence: 0.65, Fix type: code)

**What we detect:**  
A Python CrewAI tool whose body calls `print()`, matched by the predicate
`has_print_call: true`.

**Why it is flaggable:**  
The call writes to the process's stdout. Only the return value becomes the
agent's observation, so the agent never sees the output, and the line carries
no marker for which agent, task or tool call emitted it.

**Real-world consequence:**  
- A crew runs with `verbose=True` in a terminal. A tool prints a debug line,
  which appears inside the crew's narration with nothing saying which agent,
  task or tool call produced it. The agent never received it.
- The same crew runs in a deployment that captures structured records rather
  than raw stdout. The line disappears.

**Why severity is low:**  
The pack sets low and states no reasoning for it.

**Fix type — code:**  
The pack's fix is an edit to the tool source. Remove the `print()`. Emit
operator diagnostics through a module logger
(`logging.getLogger(__name__).info(...)`) so the record carries its own
module and level, and lands in the application's log sink rather than the
crew's narration stream. If the information needs to reach the agent, return
it as part of the tool's result instead.

**Confidence 0.65:**  
The pack sets 0.65 for this rule and names no false-positive or
false-negative scenarios for it.

---

## What this policy does not cover

- **Code outside a tool body.** CREW-012 is tool-scoped (`scope: tool`).
- **Languages other than Python.** The rule is declared for
  `language: python` only.
- **The deployment.** The match is the print call alone. Whether stdout is
  captured, or whether the crew runs with `verbose=True`, is not part of the
  match.
- **What the print contains.** The pack does not address the content of the
  printed output, so this document attaches no OWASP reference.
- **Project-level instrumentation.** Whether the project wires observability
  at all is CREW-202, in [tracing.md](tracing.md).

---

## Recommendations beyond the fix

```python
import logging

from crewai.tools import tool

logger = logging.getLogger(__name__)

ORDERS: dict[str, dict] = {}


@tool("lookup_order")
def lookup_order(order_id: str) -> str:
    """Look up an order by its ID, e.g. "ord_1042", and return a one-line summary of it."""
    order = ORDERS.get(order_id)
    # Operator diagnostics: a module logger, never print().
    logger.info("lookup_order order_id=%s found=%s", order_id, order is not None)
    # Agent-facing information: the return value.
    if order is None:
        return f"No order {order_id}."
    return str(order)
```

1. **Use a module logger.** `logging.getLogger(__name__).info(...)` gives the
   record its own module and level, and sends it to the application's log
   sink rather than the crew's narration stream.
2. **Put agent-facing information in the return value.** If the information
   needs to reach the agent, return it as part of the tool's result.
