---
policy_id: openai_sdk_decorator_config
category: openai_sdk
topic: decorator_config
rules:
  - id: OAI-003
    severity: medium
    confidence: 0.95
    scope: tool
    fix_type: config
  - id: OAI-004
    severity: low
    confidence: 0.7
    scope: tool
    fix_type: config
  - id: OAI-015
    severity: high
    confidence: 0.85
    scope: tool
    fix_type: config
references: [LLM05]
---

# Policy Rationale: Decorator Configuration

**Policy ID:** `openai_sdk_decorator_config`  
**File:** `openai_sdk/decorator_config.yaml`  
**Rules:** OAI-003, OAI-004, OAI-015  
**Severities:** medium, low, high  
**Fix types:** config, config, config  
**References:** LLM05

---

## What this policy covers

The keyword arguments passed to the OpenAI Agents SDK `@function_tool` decorator
that govern runtime safety, read from `ToolDef.Config` (captured by discovery from
the decorator call). OAI-003 fires on `strict_mode=False`
(`tool_decorator_kwarg_value`); OAI-004 on the *absence* of
`failure_error_function` (`not tool_decorator_kwarg_present`); OAI-015 on the
explicit `failure_error_function=None`. The three describe a spectrum from the safe
default, through an omitted safeguard, to a deliberately dangerous setting.

---

## Why decorator configuration is a distinct concern in agent tools

The decorator is where the OpenAI SDK wires the two contracts that sit between the
model and the tool body: the *input* contract (the JSON schema the model must
satisfy) and the *output-on-failure* contract (what the model sees when the tool
raises). Both default to safe — strict schema enforcement on, structured error
surfacing on — so the only way to end up unsafe is to opt out. These rules detect
the opt-outs.

`strict_mode=False` relaxes schema enforcement, so the model's arguments are no
longer validated against the tool's type hints before the body runs; loosely-typed
or malformed values reach the function and cause silent type errors or crashes
mid-execution. The two `failure_error_function` rules concern the egress contract:
by default a tool exception is converted to a string the model can reason about,
but `failure_error_function=None` re-raises instead, aborting the entire agent run
on a single tool failure. This is OWASP LLM05 (Improper Output Handling) at the
configuration layer — the tool's input and failure outputs are handled in ways the
model cannot safely consume.

These are *config* fixes: each is a decorator keyword argument, changed without
touching the tool's logic.

---

## Rule-by-rule defense

### OAI-003 — Tool sets strict_mode=False (Severity: medium, Confidence: 0.95, Fix type: config)

**What we detect:** `@function_tool(strict_mode=False)` (`tool_decorator_kwarg_value`).

**Why it is flaggable:** it relaxes runtime JSON-schema enforcement, so the model
can pass arguments that violate the tool's type hints.

**Real-world consequence:** a tool typed `count: int` receives `count="five"` and
crashes or coerces silently mid-operation.

**Why severity is medium and not high:** it causes wrong-argument execution, not a
direct breach, and usually surfaces as an error rather than a silent compromise.

**Fix type — config:** remove the kwarg (default `True` is safe); if a specific
input shape needed the relaxation, widen the type hints instead.

**Confidence 0.95:** the literal `False` value is read directly — almost no false
positives.

### OAI-004 — Tool has no failure_error_function (Severity: low, Confidence: 0.7, Fix type: config)

**What we detect:** a `@function_tool` with no `failure_error_function` kwarg.

**Why it is flaggable:** on a raised exception the SDK surfaces the raw string to the
model, which then has no recovery contract and may hallucinate retries.

**Real-world consequence:** a transient failure is shown to the model as an opaque
traceback; it retries a non-retryable action or abandons a recoverable one.

**Why severity is low:** this flags the *absence* of an optional safeguard whose
default behavior is already tolerable, and many tools never raise or handle errors
in-body, so it fires on a lot of correct code; it is a hygiene nudge, not a defect.

**Fix type — config:** pass a `failure_error_function` that returns a structured
error string.

**Confidence 0.7:** a tool that cannot raise, or that handles all errors in-body and
returns a structured result, legitimately needs no `failure_error_function` — a
common false positive, hence 0.7.

### OAI-015 — Tool sets failure_error_function=None (Severity: high, Confidence: 0.85, Fix type: config)

**What we detect:** `@function_tool(failure_error_function=None)`
(`tool_decorator_kwarg_value`).

**Why it is flaggable:** `None` is not the default — it makes the SDK *re-raise* the
exception, aborting the whole agent run on one tool failure, with no model-visible
recovery path.

**Real-world consequence:** a single failing tool call tears down an entire
multi-step conversation; the user loses all progress.

**Why severity is high and not medium:** it converts a recoverable tool error into a
run-ending failure — a denial of the whole interaction, distinct from OAI-004's
merely-absent safeguard.

**Fix type — config:** remove `=None` or replace with a structuring function; keep
`None` only if external error handling intentionally wants hard-fail semantics, and
document it.

**Confidence 0.85:** the literal `None` is read directly; the gap is the rare case
where hard-fail is the deliberate, externally-handled design.

---

## What this policy does not cover

- The *quality* of a `failure_error_function` that is present — it may return
  unstructured or leaky text and still pass OAI-004/015.
- `strict_mode` left at default but undermined by untyped parameters (OAI-002) — the
  schema is only as strict as the hints it is built from.
- Decorator kwargs supplied dynamically (a variable, not a literal) that the
  scanner cannot resolve.
- Runtime exceptions that escape regardless of configuration (e.g. raised before the
  SDK wrapper is entered).

---

## Recommendations beyond the fix

```python
from agents import function_tool

def _on_failure(exc: Exception, ctx) -> str:
    # Structured, model-readable, no internal detail.
    return '{"error": "tool failed", "retryable": false}'

@function_tool(strict_mode=True, failure_error_function=_on_failure)
def set_quantity(sku: str, count: int) -> dict:
    """Set the stock count for a SKU."""
    ...
```

1. Leave `strict_mode` at its default `True`; fix argument-shape problems by
   adjusting type hints, never by relaxing enforcement.
2. Provide a `failure_error_function` that returns a structured `{error, retryable}`
   payload, mirroring the in-body error contract (see `error_handling`, OAI-008).
3. Never ship `failure_error_function=None` on a tool that can raise unless an outer
   handler deliberately wants the run to abort — and say so in a comment.
