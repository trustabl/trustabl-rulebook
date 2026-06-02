---
policy_id: openai_sdk_observability
category: openai_sdk
topic: observability
rules:
  - id: OAI-010
    severity: low
    confidence: 0.65
    scope: tool
    fix_type: code
references: [LLM02]
---

# Policy Rationale: Observability Hygiene

**Policy ID:** `openai_sdk_observability`  
**File:** `openai_sdk/observability.yaml`  
**Rules:** OAI-010  
**Severities:** low  
**Fix types:** code  
**References:** LLM02

---

## What this policy covers

This policy targets OpenAI Agents SDK `@function_tool` bodies that write diagnostics to standard output via the built-in `print()`. The detection is the structured `has_print_call` predicate: it walks the function's AST and fires on any call whose callee is the bare builtin `print`. Because it matches the callee symbol rather than a substring, lookalike callees such as `pprint(...)` (from `pprint`) do not fire.

---

## Why stdout diagnostics are a distinct concern in agent tools

In a conventional script, `print()` is a reasonable way to surface progress — a human is watching the terminal. A `@function_tool` has no human watching: only the function's *return value* flows back into the agent loop, so anything sent to `print()` is invisible to the model. The diagnostic the author meant as "show me what happened" never reaches the one consumer (the model) that decides what to do next, and in production it usually never reaches the operator either — structured log pipelines capture `logging` records and JSON, not raw process stdout, so the print silently evaporates exactly when an incident makes you want it.

The sharper, agent-specific failure is transport corruption. The Model Context Protocol's stdio transport uses the process's **stdout as the wire** — newline-delimited JSON-RPC frames. A tool that is reachable over an MCP stdio server and calls `print("debug")` interleaves loose text between JSON-RPC messages on that same channel. The client's parser then sees malformed frames: responses get dropped, the session desyncs, and the failure looks like an intermittent protocol bug far from its cause. Unlike a missing log line, this is a hard break, not a cosmetic one — and the tool author who added the `print` for local debugging has no signal that the same tool will corrupt a stdio transport in another deployment.

There is a smaller security edge. Diagnostic prints frequently embed values the tool is handling — `print(f"calling billing API key={api_key}")`, `print(resp.json())` — and whatever captures the process's stdout (container logs, a shared journald sink, a log-aggregation service) then holds that data. In an agentic system the values passing through a tool often include credentials, user PII, or upstream tool output, so a careless diagnostic becomes a sensitive-information-disclosure path into log storage with a different (usually broader) audience than the agent itself. This is the LLM02 angle; it is secondary to the reliability concern but real.

---

## Rule-by-rule defense

### OAI-010 — Tool function prints to stdout for diagnostics (Severity: low, Confidence: 0.65, Fix type: code)

**What we detect:**
A `@function_tool`-decorated function whose body calls the bare builtin `print` (predicate `has_print_call`, an AST call-node walk on the callee symbol). Attribute calls and other callees whose names merely contain `print` — `pprint(...)`, `rich.print(...)`, `console.print(...)` — are not matched.

**Why it is flaggable:**
A `print()` in a tool body is output sent to a channel no agent consumer reads, and — when the tool is served over MCP stdio — to a channel that is actively load-bearing for the protocol. The presence of the call is the signal: the author routed information to stdout instead of to the return value (which the model reads) or a logger (which operators read).

**Real-world consequence:**
- A `lookup_order(order_id: str)` tool calls `print(f"DEBUG resolved {order_id} -> {row}")`. In production behind a JSON log pipeline the line is dropped; when a customer disputes a lookup there is no trace of what the tool saw.
- The same tool is later exposed through an MCP stdio server. Each `print` now emits a non-JSON line on stdout between JSON-RPC frames; the MCP client raises parse errors and intermittently loses tool responses, presenting as a flaky agent.
- `charge_card(...)` calls `print("charging", amount, "with", api_key)` for local debugging. The container's stdout is shipped to a shared logging backend, and the API key now sits in log storage readable by anyone with log access.

**Why severity is low and not medium:**
In the common case this is a reliability/observability degradation, not an exploit — a missing log line or a noisy stream. The two ways it escalates (stdio-transport corruption, secret-to-log disclosure) are both *conditional*: the first only bites when the tool is served over an MCP stdio transport, the second only when sensitive values are printed and stdout is captured to a broader audience. Neither is guaranteed by the mere presence of `print()`, so the rule stays at `low`. It is not `info` because the transport-corruption case is a hard functional break, not a style nit — and `info` is reserved.

**Fix type — code:**
Removing the `print()` or replacing it with a module logger / a field in the return value is an edit to the tool source. No guardrail, hook, or agent constructor kwarg changes how a tool body writes to stdout.

**Confidence 0.65:**
The gap reflects genuine ambiguity about whether a given `print` is a problem in the tool's actual deployment, which the rule cannot see. False positives: a tool intentionally run only over a non-stdio transport (HTTP/SSE) where stdout is harmlessly captured, or `print(..., file=some_stream)` redirecting away from stdout — the rule does not inspect the `file=` keyword, so a redirected print still fires. False negatives: diagnostics written through `sys.stdout.write(...)`, `os.write(1, ...)`, or a logger that has been misconfigured to emit on stdout are not `print` calls and are not detected. The 0.65 says: the pattern is reliably *present* when flagged, but whether it is *harmful* depends on transport and on what is printed — both outside the rule's view.

---

## What this policy does not cover

- `sys.stdout.write(...)` / `os.write(1, ...)` — direct stream writes that bypass the `print` builtin.
- A logger configured (or misconfigured) with a `StreamHandler` pointing at stdout — that is a configuration issue, not a `print` call, and is invisible to the rule.
- `print(..., file=sys.stderr)` or `print(..., file=open(...))` — these do not reach stdout, but the rule fires anyway because it does not read the `file=` keyword. A reviewer must confirm the destination.
- `pprint`, `rich.print`, `click.echo`, `console.print` — higher-level printers that also reach stdout but are not the bare builtin. The rule deliberately matches only `print` to avoid the `pprint(`-style false positive that substring matching produced.
- Whether the tool is actually served over an MCP stdio transport. The transport-corruption risk is *potential*; the rule flags the precondition, not a confirmed break.

---

## Recommendations beyond the fix

```python
from agents import function_tool
import logging

logger = logging.getLogger(__name__)


@function_tool
def lookup_order(order_id: str) -> dict:
    """Look up an order by ID. Returns {order: {...}} on success or
    {error: str, retryable: bool} if the order is not found."""
    row = _orders.get(order_id)
    # Diagnostics go to the application's log sink — never to stdout, which
    # the model cannot read and which is the MCP stdio protocol channel.
    logger.info("lookup_order resolved", extra={"order_id": order_id, "found": row is not None})
    if row is None:
        return {"error": f"no order {order_id}", "retryable": False}
    # Information the model needs goes in the return value, not print().
    return {"order": row, "note": "fetched from primary store"}
```

1. Route operational diagnostics through `logging.getLogger(__name__)`, not `print()`. The application configures handlers/sinks centrally; the tool should not assume stdout is safe to write.
2. If the model needs to *see* a diagnostic (why a lookup failed, which branch ran), put it in the structured return value — that is the only channel the model reads.
3. Never log or print secrets, raw credentials, or full upstream responses. Log identifiers and booleans (`order_id`, `found=true`), not payloads.
4. If the tool may ever be served over an MCP stdio server, treat *any* stdout write as a protocol violation and gate it out in review — stdout belongs to the transport.
5. In CI, consider a lint that fails on `print(` inside `@function_tool` bodies, so the pattern is caught before it ships rather than after a stdio session desyncs.
