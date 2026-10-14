---
policy_id: claude_sdk_observability
category: claude_sdk
topic: observability
rules:
  - id: CSDK-019
    severity: low
    confidence: 0.65
    scope: tool
    fix_type: code
references: []
---

# Policy Rationale: Claude Agent SDK Tool Observability Hygiene

**Policy ID:** `claude_sdk_observability`  
**File:** `claude_sdk/observability.yaml`  
**Rules:** CSDK-019  
**Severities:** low  
**Fix types:** code  
**References:** none

---

## What this policy covers

How a Claude Agent SDK tool emits diagnostics. The policy has one rule,
CSDK-019, which applies to Python Claude Agent SDK tools (`applies_to:
claude_sdk_tool`, `language: python`, `scope: tool`) and matches a tool whose
body contains a print call (`has_print_call: true`). A tool body that prints to
stdout writes somewhere neither the model nor the application's log sink reads,
and can corrupt a transport that uses stdout as a protocol channel.

---

## Why stdout diagnostics are a distinct problem in Claude Agent SDK tools

In a Claude Agent SDK tool, `print()` reaches none of the consumers that matter.

- **The model never sees it.** Only the tool's return value flows back into the
  agent loop. Anything the tool prints is invisible to the model, and in any
  deployment that captures structured records rather than raw stdout it
  silently disappears for the operator as well.
- **An MCP stdio transport carries JSON-RPC on stdout.** When the tool is served
  to the agent over an MCP stdio transport, stdout carries the JSON-RPC frames.
  A loose print interleaves with them, and the client hits a parse error on a
  line that is not JSON.
- **A programmatic host is reading the SDK's message stream.** When the SDK is
  driven programmatically, the host application is reading the SDK's own
  message stream. Tool prints land interleaved with it rather than in the
  application's logs, attributable to no particular turn or tool call.

The first point makes a print a lost log line. The other two make it worse than
that: the output lands in a channel that something else is reading.

---

## Rule-by-rule defense

### CSDK-019 — Tool prints to stdout for diagnostics (Severity: low, Confidence: 0.65, Fix type: code)

**What we detect:**
A Python Claude Agent SDK tool whose body calls `print()`, matched by the
predicate `has_print_call: true`.

**Why it is flaggable:**
The call writes diagnostics to the process's stdout. Only the tool's return
value reaches the model, and stdout is not the application's log sink, so the
print sends information to a channel no intended consumer reads. Where stdout
is a protocol channel, the print also writes into that channel.

**Real-world consequence:**
- The tool is served over an MCP stdio transport. Its print interleaves with
  the JSON-RPC frames on stdout, and the client hits a parse error on a line
  that is not JSON.
- The SDK is driven programmatically. The tool's prints land interleaved with
  the SDK message stream the host application is reading, not in the
  application's logs, and they cannot be attributed to a particular turn or
  tool call.

**Fix type — code:**
The fix is an edit to the tool source: remove the `print()`, emit operator
diagnostics through a module logger, and put anything the model needs in the
tool's return value.

**Confidence 0.65:**
The pack sets confidence at 0.65 for this rule. It states no known false
positives, false negatives, or other limits for CSDK-019.

---

## What this policy does not cover

- **Code outside a tool body.** CSDK-019 is tool-scoped. A print in the host
  application, such as one that echoes SDK messages, is not a tool body and is
  outside this rule.
- **Languages other than Python.** The rule is declared for `language: python`
  only.
- **The deployment.** The match is the print call alone. Whether the tool is
  actually served over an MCP stdio transport, or driven by a programmatic host,
  is not part of the match.
- **What the print contains.** The pack does not address the content of the
  printed output, so this document attaches no OWASP reference.
- **Project-level observability wiring.** Whether the project wires tracing at
  all is CSDK-208 in [tracing.md](tracing.md).

---

## Recommendations beyond the fix

```python
import logging

from claude_agent_sdk import tool

logger = logging.getLogger(__name__)


@tool("lookup_order", "Look up an order by ID", {"order_id": str})
async def lookup_order(args):
    row = ORDERS.get(args["order_id"])
    # Operator diagnostics: a module logger, never print().
    logger.info("lookup_order order_id=%s found=%s", args["order_id"], row is not None)
    # Model-facing information: the return value.
    if row is None:
        return {"content": [{"type": "text", "text": f"No order {args['order_id']}"}]}
    return {"content": [{"type": "text", "text": str(row)}]}
```

```python
# Application entry point, where the tool may be served over a stdio transport:
# send log records to stderr, which the transport leaves alone.
import logging
import sys

logging.basicConfig(stream=sys.stderr, level=logging.INFO)
```

1. **Use a module logger.** `logging.getLogger(__name__).info(...)` gives the
   record its module and level, and it lands in the application's log sink.
2. **Point the handler at stderr for stdio.** Where the tool may be served over
   a stdio transport, make sure the handler writes to stderr, which the
   transport leaves alone.
3. **Put model-facing information in the return value.** If the model needs the
   information, include it in what the tool returns. That is the only channel
   that reaches the agent loop.
