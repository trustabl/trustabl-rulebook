---
policy_id: autogen_error_handling
category: autogen
topic: error_handling
rules:
  - id: AG2-013
    severity: low
    confidence: 0.6
    scope: tool
    fix_type: code
references: [LLM05]
---

# Policy Rationale: AutoGen Error Contract Hygiene

**Policy ID:** `autogen_error_handling`  
**File:** `autogen/error_handling.yaml`  
**Rules:** AG2-013  
**Severities:** low  
**Fix types:** code  
**References:** LLM05 (Improper Output Handling)

> Shares the structured-error threat model with
> [openai_sdk/error_handling.md](../openai_sdk/error_handling.md). AutoGen-specific
> angle only.

---

## What this policy covers

An AutoGen / AG2 tool — a function registered with `register_function`,
`register_for_llm` / `register_for_execution`, or an equivalent binding — whose
body contains a `raise` and no `try`/`except`, detected by
`all: [has_raise: true, has_try_except: false]`.

---

## Why error handling is a distinct concern in agent tools

AutoGen's unit of state is the conversation. A tool's return value does not go
to a caller that inspects it and discards it; it becomes a tool-response message
appended to the chat history, and that history is re-sent to the model on every
subsequent turn. An uncaught exception therefore does not fail once. It is
stringified into a message that persists, and every later turn pays for it in
context.

That persistence is what distinguishes the AutoGen case. In a
request/response tool loop a bad error string costs one turn's confusion. Here it
is replayed for the remainder of the run, and in a group chat it is broadcast:
`GroupChatManager` sends the shared transcript to each participant when selecting
and prompting the next speaker, so one tool's traceback is read by every agent in
the chat, on every round, whether or not it is relevant to them. A single verbose
Python traceback in a five-agent chat is re-tokenized dozens of times before the
run ends. The failure mode is not only that the model cannot recover — it is that
the record of the failure crowds out the context needed to do anything else.

Recovery is degraded in the ordinary way as well: the message carries no field
separating a malformed argument from an unreachable dependency, so the model
re-calls the tool identically, or hands the failure to another agent as prose,
which does not have the call site either. And because the stringified exception
is permanent chat state, any path, hostname or connection string in `str(e)` is
carried into every participant's context and into the exported transcript
(improper output handling, LLM05).

---

## Rule-by-rule defense

### AG2-013 — AutoGen tool raises exceptions without a structured error contract (Severity: low, Confidence: 0.6, Fix type: code)

**What we detect:**  
A tool function body containing at least one `raise` statement and no
`try`/`except` block anywhere in that body.

**Why it is flaggable:**  
Every failure the function can produce leaves it as an exception, so the
tool-response message that lands in the conversation is a stringified traceback.
The model has no field to branch on, and the bad message is now durable state.

**Real-world consequence:**

- A `load_profile` tool raises `KeyError` on an unknown name. The assistant sees
  `KeyError: 'jdoe'`, re-calls with `jdoe`, and both the failure and the retry
  stay in history — re-sent on every following turn for the rest of the run.
- In a five-agent `GroupChat`, a tool raising a full `sqlalchemy` traceback puts
  that traceback in the shared transcript. The manager includes it when prompting
  each speaker, so it is re-read on every round by agents with no relation to the
  tool.
- A tool raising `FileNotFoundError` leaks the absolute path of a server-side
  file into the permanent transcript, which is then exported for evaluation.

**Why severity is low and not medium:**  
The impact is degraded recovery and context waste plus an incidental disclosure
channel; it grants no capability and crosses no privilege boundary. A raise is
often deliberate, with the executor agent or a wrapping frame expected to
structure it. Low matches the equivalent rules in the Claude, OpenAI, ADK and MCP
packs.

**Fix type — code:**  
Returning `{"error": ..., "retryable": ...}` instead of raising is a source edit
to the registered function.

**Confidence 0.6:**  
The check is body-local. False positives: a function that raises because a
decorator or the executor agent converts the exception into the structured shape
the rule asks for. False negatives: a `try`/`except` that catches and re-raises,
or returns a bare string, satisfies the predicate while providing no contract.
0.6 reflects a single-frame syntactic check standing in for a whole-call-path
property.

---

## What this policy does not cover

- Exception handling by a wrapping frame — a decorator, or the executor agent's
  own handling — outside the tool body.
- A `try`/`except` that catches and re-raises, or returns an unstructured string.
- Whether the structured error is correct, or whether `retryable` reflects
  reality.
- Whether the message actually contains sensitive data.
- Context growth from successful tool responses; the rule addresses the error
  path only.

---

## Recommendations beyond the fix

```python
from autogen import register_function


def load_profile(name: str) -> dict:
    """Load a profile by name."""
    try:
        return {"ok": True, "profile": PROFILES[name]}
    except KeyError:
        return {"ok": False, "error": "no profile with that name", "retryable": False}
    except TimeoutError:
        return {"ok": False, "error": "profile service timed out", "retryable": True}


register_function(load_profile, caller=assistant, executor=user_proxy,
                  description="Load a profile by name.")
```

1. Return a `retryable` field on every failure path, so the next speaker can tell a
   bad argument from a transient outage.
2. Keep error payloads short. The tool response becomes permanent conversation
   state, re-sent on every later turn — a full traceback is a recurring context
   cost, not a one-off. A single-sentence message beats a stack dump.
3. In a `GroupChat`, remember the transcript reaches every participant when the
   manager prompts the next speaker. Write the error so an agent unrelated to the
   tool can skip past it.
4. Never pass a raw `str(e)` from a database or filesystem client through; it lands
   in the exported transcript.
