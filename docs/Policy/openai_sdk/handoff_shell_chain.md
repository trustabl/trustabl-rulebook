---
policy_id: openai_sdk_handoff_shell_chain
category: openai_sdk
topic: handoff_shell_chain
rules:
  - id: OAI-210
    severity: medium
    confidence: 0.5
    scope: agent
    fix_type: code
  - id: OAI-211
    severity: low
    confidence: 0.5
    scope: agent
    fix_type: code
references: [LLM01, LLM06]
---

# Policy Rationale: Handoff Chain Reaches Shell Execution

**Policy ID:** `openai_sdk_handoff_shell_chain`  
**File:** `openai_sdk/handoff_shell_chain.yaml`  
**Rules:** OAI-210, OAI-211  
**Severities:** medium, low  
**Fix types:** code  
**References:** LLM01 (Prompt Injection), LLM06 (Excessive Agency)

> **Verification status.** The guardrail behavior below was read on 2026-11-26 as raw text
> from the OpenAI Agents SDK documentation source, `docs/guardrails.md` on the `main` branch
> of `github.com/openai/openai-agents-python`. The three arXiv papers that the source sheet
> names (2609.00267, 2608.15888, 2609.08371) were read the same day; they discuss delegation
> and authority in general, none names this SDK, and they are not relied on. **Not
> verified, and therefore not assumed:** how the SDK versions before the one documented
> treat guardrails on a handoff; whether the SDK's `input_filter` on a handoff changes the
> result for a given payload; and how common handoff chains that reach shell tools occur in
> real repositories (none occurred in the public sample for this batch).

---

## What this policy covers

An OpenAI Agents SDK agent can hand a turn to another agent. This policy has two rules that
read the same chain, an agent that does not wield shell itself and reaches, through its
resolved handoff targets, an agent that does. **OAI-210** is the case with no
`input_guardrails` on the entry agent; **OAI-211** is the case with them. One agent matches
at most one of the two.

---

## Rule-by-rule defense

### OAI-210 — Agent with no input_guardrails reaches a shell-executing agent through its handoffs (Severity: medium, Confidence: 0.5, Fix type: code)

**What we detect:** an agent with no `input_guardrails` kwarg, and no shell tool of its own,
whose resolved handoff chain contains an agent that has a shell-invocation tool, a tool
that calls `subprocess` or `os.system`, or a hosted `ShellTool`, `LocalShellTool`,
`ApplyPatchTool` or `CodeInterpreterTool`. The walk follows resolved targets with a visited
set, so a cycle or a self edge ends it. Gated by `transitive_capability_exceeds_direct`.

What is not flagged: an agent that has a shell tool itself; a chain with no shell agent; an
unresolved or external target, a target in another file, and a target built by a factory;
and an agent that declares `input_guardrails` (OAI-211).

**Why it is flaggable.** The guardrails page states that input guardrails run for the first
agent in the chain, and, in its admonition, that an agent's input guardrails run when that
agent is the first agent. An entry agent with no `input_guardrails` passes the user's
message on with no guardrail having run, and a delegated agent's own guardrails do not run
on the delegated turn.

**Real-world consequence:** a message that nothing screened can steer a handoff to an agent
that runs shell commands.

**Why severity is medium:** The pack sets medium and states no reasoning for it.

**Fix type — code:** the fix edits the agents. The pack's fix is to add `input_guardrails` to
the agent that receives the user's input, review whether the downstream agent needs shell
access, and constrain the delegated payload with an `input_filter` and validation inside the
shell tool.

**Confidence 0.5:** the pack's explanation states these limits of the check:

- It reads handoff targets that discovery resolves to an agent in the same file.
- The check cannot tell which agent receives the user's input; an agent in the middle of a
  chain is judged the same as the entry agent, and its own guardrails would not run in that
  position.
- An `input_filter` on the handoff, tool-level validation and approval settings on the
  shell tool are not read.
- A shell tool on the agent itself is the concern of the direct shell rules.

### OAI-211 — Agent with input_guardrails reaches a shell-executing agent through its handoffs (Severity: low, Confidence: 0.5, Fix type: code)

**What we detect:** the same chain as OAI-210, on an agent that declares `input_guardrails`.
Gated by `agent_kwarg_present` and `transitive_capability_exceeds_direct`.

**Why it is flaggable.** The same guardrails-page statements apply: the guardrails screen the
user's message when this agent is the entry agent and do not run again on the delegated
turn. The text that reaches the shell tool is the handoff payload, which the model wrote.

**Why severity is low:** The pack sets low. Its explanation states that the rule is rated
lower than OAI-210 because the guardrails here screen the user's message at the entry point.

**Fix type — code:** the pack's fix is to validate the delegated payload with an
`input_filter` on the handoff and a check inside the shell tool, and to review whether the
downstream agent needs shell access.

**Confidence 0.5:** the pack's explanation states these limits of the check:

- It reads handoff targets that discovery resolves to an agent in the same file.
- It does not read what the guardrails test, an `input_filter`, or validation inside the
  shell tool, and it cannot tell whether the agent is the entry agent.

The pack states no other limits for these rules.

---

## What this policy does not cover

- Shell tools reached through a handoff target in another file or a factory.
- Capabilities other than shell, such as file writes or network egress.
- Tool guardrails on the shell tool; the guardrails page says built-in execution tools do
  not use that pipeline.
- Agents wired through `Agent.as_tool()` rather than `handoffs`.

---

## Recommendations beyond the fix

1. Put `input_guardrails` on the agent that receives the user's input.
2. Give the shell-executing agent the narrowest command surface it needs, and validate
   commands inside the tool.
3. Use an `input_filter` on the handoff to control what the downstream agent sees.

---

## Sources

Retrieved 2026-11-26.

- OpenAI Agents SDK documentation, `docs/guardrails.md`,
  `github.com/openai/openai-agents-python`, `main` branch. Cited for the statements that
  input guardrails run for the first agent in the chain, and nothing more.
