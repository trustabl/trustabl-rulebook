---
policy_id: crewai_error_handling
category: crewai
topic: error_handling
rules:
  - id: CREW-008
    severity: low
    confidence: 0.6
    scope: tool
    fix_type: code
references: []
---

# Policy Rationale: CrewAI Error Contract Hygiene

**Policy ID:** `crewai_error_handling`  
**File:** `crewai/error_handling.yaml`  
**Rules:** CREW-008  
**Severities:** low  
**Fix types:** code  
**References:** none

---

## What this policy covers

How a CrewAI tool surfaces failure. The policy has one rule, CREW-008, which
applies to Python CrewAI tools (`applies_to: crewai_tool`, `language: python`,
`scope: tool`) that raise an exception they never catch. The match is `all:`
of two predicates: `has_raise: true` and `has_try_except: false`.

---

## Why the error contract is a distinct concern in CrewAI tools

A tool that raises hands the agent a stringified exception in place of a
result. When the exception reaches the agent, it arrives as text. The tool
itself defines no failure-mode name and no retry signal; whether the text
carries either depends on whatever message the exception holds. If the agent
re-calls the same tool the same way, each attempt spends one of its
[CREW-110](agent_safety.md) `max_iter` steps.

The damage does not stop at that agent. In a crew that runs its tasks in
sequence, each task's output is threaded forward as context, so an unusable
error string can become the input the tasks behind it reason over. The raw
message also crosses into the conversation intact, carrying whatever internal
detail it held, such as file paths, hostnames or query fragments.

---

## Rule-by-rule defense

### CREW-008 — CrewAI tool raises without a structured error contract (Severity: low, Confidence: 0.6, Fix type: code)

**What we detect:**  
A CrewAI tool whose body contains a `raise` (`has_raise: true`) and has no
`try`/`except` block (`has_try_except: false`), both under `all:`.

**Why it is flaggable:**  
The mechanism is the one stated
[above](#why-the-error-contract-is-a-distinct-concern-in-crewai-tools): the
exception escapes the tool and reaches the agent as text. The tool defines no
failure-mode name and no retry signal, so whatever the text says is down to
the message the exception holds.

**Real-world consequence:**  
A `lookup_order(order_id: str)` tool raises `KeyError` when the lookup
misses. In Python, `str(KeyError("ord_1042"))` is `'ord_1042'`, the quoted
key, so the text the agent receives is built from a message that names
neither the failure nor whether a retry could help. If the agent re-calls the
tool with the same `order_id`, each attempt spends a `max_iter` step. If its
task output carries the error text, the tasks behind it reason over that
text.

**Why severity is low:**  
The pack sets low and states no reasoning for it. The costs the explanation
names are spent `max_iter` steps, an unusable error string threaded forward
to downstream tasks, and internal detail carried in the raw message.

**Fix type — code:**  
The pack's fix is an edit to the tool source. Catch the failure modes you
expect and return a structured string the agent can act on, rather than
letting the exception escape: name the failure, and say plainly whether
retrying could help and what would have to change. Reserve raising for
programmer errors the agent genuinely cannot work around.

**Confidence 0.6:**  
The pack sets 0.6 for this rule and names no false-positive or
false-negative scenarios for it.

---

## What this policy does not cover

- **Tools with a `try`/`except` block.** The match requires
  `has_try_except: false`, so a tool with a `try`/`except` block does not
  fire.
- **Raises the fix keeps.** The fix reserves raising for programmer errors,
  and the match has no predicate that tells those apart, so a tool whose only
  `raise` is such an error still matches.
- **What the exception message contains.** The explanation names internal
  detail in the message as a risk, but no predicate looks at the message.
- **Languages other than Python.** The rule is declared for
  `language: python` only.
- The pack states no other limits for this rule.

---

## Recommendations beyond the fix

```python
from crewai.tools import tool

ORDERS: dict[str, dict] = {}


@tool("lookup_order")
def lookup_order(order_id: str) -> str:
    """Look up an order by its ID, e.g. "ord_1042", and return the order record or an error string that says whether retrying could help."""
    if not order_id.startswith("ord_"):
        # The agent can fix this: say what would have to change.
        return 'Error: invalid_order_id. Retrying can help: order_id must start with "ord_", e.g. "ord_1042".'
    try:
        order = ORDERS[order_id]
    except KeyError:
        # A retry cannot help: say so.
        return "Error: order_not_found. Retrying with the same order_id will not help."
    return str(order)
```

1. Catch the failure modes you expect and return a structured string that
   names the failure, says whether retrying could help, and says what would
   have to change.
2. Reserve raising for programmer errors the agent genuinely cannot work
   around.
3. Keep internal detail such as file paths, hostnames and query fragments out
   of the strings a tool returns or raises.
4. Size the agent's `max_iter` to its role ([CREW-110](agent_safety.md)), the
   cap on the steps spent re-calling a failing tool.
