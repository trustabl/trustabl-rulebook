---
policy_id: openai_sdk_consequential_tool_gate
category: openai_sdk
topic: consequential_tool_gate
rules:
  - id: OAI-212
    severity: high
    confidence: 0.4
    scope: agent
    fix_type: code
references: [LLM06]
---

# Policy Rationale: OpenAI Agents SDK Agent With a Side-Effecting Tool and No Approval

**Policy ID:** `openai_sdk_consequential_tool_gate`  
**File:** `openai_sdk/consequential_tool_gate.yaml`  
**Rules:** OAI-212  
**Severities:** high  
**Fix types:** code  
**References:** LLM06

> **Verification status.** The paper cited below was read on 2026-11-27 as the abstract on its
> arXiv page. The SDK pages named in Sources were retrieved on 2026-11-27 and the quotations in
> the rule come from them. **Not verified, and therefore not assumed:** that the paper's attacks
> work against OpenAI Agents SDK; that a tool with one of the name words below changes anything outside
> the process; what share of repos have such a tool without a gate.

---

## What this policy covers

This policy has one rule. **OAI-212** is agent scope. It reads the agent's constructor call and the
tools resolved from its tools list, and reports an agent that holds a tool with a side effect and
shows no decision point before the call. It reports one finding for each agent, attributed to the
constructor call. The pack loads when the repo imports OpenAI Agents SDK.

---

## Rule-by-rule defense

### OAI-212 - Agent holds a send, pay, delete or deploy tool with no needs_approval (Severity: high, Confidence: 0.4, Fix type: code)

**What we detect:** an agent, gated by `agent_consequential_tool_ungated`, that holds a tool with
a name that starts with one of the name words and no gate. The gates read are the `needs_approval` and `tool_input_guardrails` kwargs of `@function_tool` (a value other than `False`), and the same two names set as an attribute on the tool variable after it is built.

**Why it is flaggable.** The OpenAI Agents SDK human-in-the-loop page describes `needs_approval` as the way to "pause agent execution until a person approves or rejects sensitive tool calls", and its guardrails page describes tool input guardrails as checks that run before the tool executes and that "can skip the call, replace the output with a message, or raise a tripwire". *Blocking at the Boundary* (arXiv 2610.05163, submitted 4
October 2026) states in its abstract that "Stopping such attacks requires a decision before each
consequential action". A tool with a side effect and no such option leaves the call to the model
alone. The paper is cited for that statement and nothing more.

**Real-world consequence:** a call that the model makes, including one steered by text the agent
read, runs without a person or a policy having seen it.

**Why severity is high:** The pack sets high and states no reasoning for it.

**Fix type - code:** set `needs_approval=True` (or a callable) on the `@function_tool` decorator and handle `result.interruptions`, or put a deterministic check in `tool_input_guardrails`.

**Confidence 0.4:** the pack's explanation states these limits:

- The name words are send_, notify_, refund_, charge_, pay_, payout_, transfer_, delete_, drop_, destroy_, deploy_, publish_, terminate_, revoke_, truncate_. The pack sets them and states no reasoning for them. A tool with a
  side effect under another name is not seen, and a tool that matches a name word and has no side
  effect is a false positive.
- A tool that shells out, evaluates code or writes a file under a neutral name is judged by OAI-014, not by this rule.
- An agent built from unpacked or non-literal arguments is not judged, a tool that discovery
  cannot resolve is not judged, and a tool imported from another module than the one that builds
  the agent is not resolved.
- A gate counts when it is present; the rule does not read what the gate decides.

---

## What this policy does not cover

- Whether a person or a policy at a layer outside this code (a gateway, a proxy, a runner that
  wraps the agent) decides before the call.
- Tools reached through hosted tools, MCP servers or handoffs.
- A tool that is gated for some arguments and not for others.

---

## Recommendations beyond the fix

1. Keep the side-effecting tools on one agent, so the gate has one place to be reviewed.
2. Log the approval decision with the call.
3. Review a change to a tool's name or gate in a pull request.

---

## Sources

- Blocking at the Boundary: Auditing Long-Horizon Agents against Staged Prompt Injection, arXiv 2610.05163, abstract retrieved 2026-11-27. Cited for the statement that stopping staged prompt injection "requires a decision before each consequential action" and for nothing more; the paper tests Claude Code and Codex, not this SDK.
- OpenAI Agents SDK, Human-in-the-loop and Guardrails pages (openai.github.io/openai-agents-python), retrieved 2026-11-27. Cited for the option names and the quoted sentences.
