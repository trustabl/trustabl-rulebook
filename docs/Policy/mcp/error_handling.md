---
policy_id: mcp_error_handling
category: mcp
topic: error_handling
rules:
  - id: MCP-006
    severity: low
    confidence: 0.6
    scope: tool
    fix_type: code
references: [LLM05]
---

# Policy Rationale: MCP Error Contract Hygiene

**Policy ID:** `mcp_error_handling`  
**File:** `mcp/error_handling.yaml`  
**Rules:** MCP-006  
**Severities:** low  
**Fix types:** code  
**References:** LLM05 (Improper Output Handling)

> Shares the structured-error threat model with
> [openai_sdk/error_handling.md](../openai_sdk/error_handling.md). This document
> covers the MCP-specific mechanism: the error is not read by a developer, it is
> read by a model that must decide what to do next, and it is the only signal
> that model receives.

---

## What this policy covers

Python MCP tool handlers (`applies_to: mcp_tool`, `language: python`) whose body
contains a `raise` statement and no `try`/`except` block. The match is
`all: [has_raise: true, has_try_except: false]`, evaluated on the handler body
only. Both conjuncts are required, so a handler that raises inside an `except`
clause does not fire, and a handler with no `raise` at all does not fire
regardless of what it lets propagate from the calls it makes.

---

## Why the error contract is a distinct concern in agent tools

An unhandled exception in a conventional API is read by a developer. It reaches
a log aggregator or a stack trace page, a human interprets it, and the
interpretation happens once, offline, by someone who can read source. The error
message is a diagnostic artifact and its audience is not part of the running
system.

Under MCP the audience is the model, in the loop, on every call. The result of a
`tools/call` is the only thing the model receives about what happened, and it
has to decide the next action from that text alone. When a handler raises, the
runtime converts the exception into a protocol-level error, and what arrives is
a message that was written to be read by a person debugging, not by a caller
choosing between "try again", "try differently", and "stop".

The consequence is that the model cannot branch. A structured result such as
`{"ok": false, "error": "rate_limited", "retryable": true}` tells it to wait and
retry. `{"ok": false, "error": "not_found", "retryable": false}` tells it to stop
asking. An opaque `KeyError: 'user_id'` tells it nothing it can act on, so it
falls back on the only strategy available without information, which is to try
the call again, often with arguments it has guessed at. That is the mechanism
connecting this rule to MCP-007: a mutating tool that raises an opaque error is a
mutating tool whose caller cannot tell "the action failed" from "the action
succeeded and the reply was lost", and a blind retry of a mutation that already
committed is a duplicate side effect.

The disclosure path runs the other way. An exception message is assembled from
whatever was in scope when it was raised, and it frequently carries absolute
filesystem paths, internal hostnames, database identifiers, and argument values.
Under a conventional deployment that text lands in a log the operator controls.
Under MCP it is returned across the server's trust boundary to the connecting
client and into the model's context, where it may be summarized to a user,
persisted in a transcript, or passed to a later tool call. Nothing about the
error text was written with that audience in mind. That is OWASP LLM05, improper
output handling: content leaving the system in a form its destination was never
designed to receive.

Severity is genuinely low, and it is worth being clear why. Neither effect is a
direct compromise. Degraded retry behavior is a reliability tax that becomes
dangerous only in combination with a mutating tool, and the disclosure is
incidental rather than attacker-directed, since an attacker cannot choose which
exception fires. The rule earns its place by being cheap to satisfy and by
sitting upstream of failures that are not cheap.

---

## Rule-by-rule defense

### MCP-006 — Tool raises exceptions without a structured error contract (Severity: low, Confidence: 0.6, Fix type: code)

**What we detect:**  
A handler body containing at least one `raise` statement and no `try`/`except`
block anywhere in that body. This is a structural check on the function's own
statements. It does not evaluate what is raised, whether the raise is reachable,
or whether anything upstream will catch it.

**Why it is flaggable:**  
A `raise` with no local handling means the exception leaves the handler. The MCP
runtime has nowhere to put it except the protocol error channel, so the model
receives a string rather than a result it can branch on. The presence of a
`raise` with no `except` is the point at which the author has decided, possibly
without meaning to, that the caller will get an exception instead of an answer.

**Real-world consequence:**

- A `get_user(user_id)` tool raises `KeyError: 'user_id'` on a malformed
  argument. The model receives the raw exception, cannot tell whether the
  argument was wrong or the user genuinely does not exist, and retries with the
  same value.
- A `create_invoice(...)` tool raises on a network failure after the write has
  already committed. The model sees a failure, retries, and the customer is
  invoiced twice. See MCP-007.
- A tool raises `FileNotFoundError: /srv/app/config/tenants/acme/keys.json`. The
  path, the deployment layout, and a tenant name all enter the transcript
  because they happened to be in the message.

**Why severity is low and not medium:**  
The direct impact is bounded. The failing call fails either way; what changes is
how legibly. The disclosure is real but incidental, since the content of an
exception message is not attacker-selected, and the model cannot be steered into
raising a chosen exception. Medium would imply that a single occurrence produces
a concrete harm on its own, and it does not. The amplifying case, a blind retry
of a committed mutation, is the harm, and that is scored on MCP-007 where the
mutation actually lives. Low is right: this is a hygiene rule whose value is
that it removes a precondition for worse failures.

**Fix type — code:**  
Converting a raise into a returned structured result changes the handler's
control flow and return shape, which is a source edit. No host configuration or
sandbox policy can turn an exception into a typed result, because nothing
outside the handler knows which failure modes are expected and which are bugs.

**Confidence 0.6:**  
The gap is that the check is body-local and shape-based. **False positives:** a
handler that deliberately raises a framework-recognized error type which the MCP
server serializes into a structured response is doing the right thing and still
fires. A handler wrapped by a decorator, middleware, or a calling frame that
catches and structures the exception fires, because the `try` is not in this
body. A `raise` inside a branch that is unreachable in practice, or a
re-raise-after-cleanup idiom expressed without `except`, fires identically.
**False negatives:** a handler that never writes `raise` but calls
`response.raise_for_status()`, indexes a dict that may not have the key, or
divides by a caller-supplied number has exactly the same opaque-error problem
and does not match, because `has_raise` is looking for the statement rather than
for the possibility. In practice this second case is the more common one, which
means the rule under-reports.

---

## What this policy does not cover

- **Exceptions raised by callees rather than by the handler.** `has_raise` looks
  for a `raise` statement in this body. A handler whose only failure path is
  `requests.get(...).raise_for_status()` or an unguarded dict lookup propagates
  the same opaque error and never matches.
- **Handling done outside the handler body.** A decorator, a middleware layer, or
  a wrapping frame that catches and structures the exception satisfies the intent
  entirely, and the rule cannot see it.
- **Whether the raised message contains anything sensitive.** The rule does not
  read the exception's content. A bare `raise ValueError("bad input")` and one
  that interpolates a connection string are treated identically.
- **Whether the returned structure is any good.** A handler with a `try`/`except`
  that catches everything and returns `{"error": "failed"}` silences the rule and
  gives the model no more to branch on than the exception did.
- **Over-broad catching.** `except Exception: pass` satisfies `has_try_except`
  and turns a failure into a silent success, which is worse than raising. This
  rule cannot distinguish it from correct handling.
- **The retry loop itself.** Whether the model retries, how often, and whether
  the tool is safe to retry are outside this predicate. MCP-007 covers the
  mutating case.
- **TypeScript MCP tools.** MCP-006 is `language: python`. A TS handler that
  throws has the identical problem and there is no `has_raise` equivalent wired
  for TypeScript in `mcp/error_handling.yaml`.

---

## Recommendations beyond the fix

```python
import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("directory")

_client = httpx.Client(base_url="https://api.internal", timeout=10.0)


@mcp.tool()
def get_user(user_id: str) -> dict:
    """Look up a user. Returns a structured result in every case so the caller
    can distinguish a missing user from a transient failure, and knows whether
    retrying is worthwhile."""
    if not user_id:
        return {"ok": False, "error": "invalid_argument",
                "detail": "user_id must be a non-empty string",
                "retryable": False}

    try:
        response = _client.get(f"/v1/users/{user_id}")
    except httpx.TimeoutException:
        return {"ok": False, "error": "timeout", "retryable": True}
    except httpx.TransportError:
        return {"ok": False, "error": "upstream_unreachable", "retryable": True}

    if response.status_code == 404:
        return {"ok": False, "error": "not_found", "retryable": False}
    if response.status_code == 429:
        return {"ok": False, "error": "rate_limited", "retryable": True,
                "retry_after_seconds": int(response.headers.get("retry-after", 5))}
    if response.status_code >= 500:
        return {"ok": False, "error": "upstream_error", "retryable": True}
    if response.status_code >= 400:
        return {"ok": False, "error": "request_rejected",
                "status": response.status_code, "retryable": False}

    return {"ok": True, "user": response.json()}
```

1. Always include a `retryable` flag. It is the single field that most changes
   what the model does next, and it is the one thing an exception message can
   never carry reliably.
2. Use a small closed set of error codes rather than free text. The model
   matches on the code; free-form prose invites it to re-interpret the same
   failure differently on each occurrence.
3. Write the `detail` field for the model, not for a log. State what the caller
   should do differently. Never interpolate a path, hostname, connection string,
   or raw argument value into it.
4. Catch specific exception types, not `Exception`. A blanket catch satisfies
   this rule while converting genuine bugs into silent successes, which is the
   failure this policy is meant to prevent, inverted.
5. Log the full exception server-side with the detail stripped from the returned
   result. The operator needs the stack trace; the model needs a code and a
   boolean.
6. For mutating tools, pair the structured error with an idempotency key so that
   a `retryable: true` response is actually safe to act on (see MCP-007).