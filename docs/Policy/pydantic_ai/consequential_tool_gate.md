---
policy_id: pydantic_ai_consequential_tool_gate
category: pydantic_ai
topic: consequential_tool_gate
rules:
  - id: PYD-204
    severity: high
    confidence: 0.4
    scope: agent
    fix_type: code
references: [LLM06]
---

# Policy Rationale: Pydantic AI Agent With a Side-Effecting Tool and No Approval

**Policy ID:** `pydantic_ai_consequential_tool_gate`  
**File:** `pydantic_ai/consequential_tool_gate.yaml`  
**Rules:** PYD-204  
**Severities:** high  
**Fix types:** code  
**References:** LLM06

> **Verification status.** The paper cited below was read on 2026-11-27 as the abstract on its
> arXiv page. The SDK pages named in Sources were retrieved on 2026-11-27 and the quotations in
> the rule come from them. **Not verified, and therefore not assumed:** that the paper's attacks
> work against Pydantic AI; that a tool with one of the name words below changes anything outside
> the process; what share of repos have such a tool without a gate.

---

## What this policy covers

This policy has one rule. **PYD-204** is agent scope. It reads the agent's constructor call and the
tools resolved from its tools list, and reports an agent that holds a tool with a side effect and
shows no decision point before the call. It reports one finding for each agent, attributed to the
constructor call. The pack loads when the repo imports Pydantic AI.

---

## Rule-by-rule defense

### PYD-204 - Agent holds a side-effecting tool with no requires_approval (Severity: high, Confidence: 0.4, Fix type: code)

**What we detect:** an agent, gated by `agent_consequential_tool_ungated`, that holds a tool with
a name that starts with one of the name words, or a body that runs a subprocess, evaluates code or writes a file, and no gate. The gates read are `requires_approval` on the tool decorator or `Tool(...)` (a value other than `False`), a raise of `ApprovalRequired` in the tool body, and the name `requires_approval` in the text of any agent kwarg.

**Why it is flaggable.** The Pydantic AI deferred tools page describes `requires_approval=True` on the tool decorators, the `Tool` class and toolsets, and raising `ApprovalRequired` inside a tool, as the way to require approval of a tool call. *Blocking at the Boundary* (arXiv 2610.05163, submitted 4
October 2026) states in its abstract that "Stopping such attacks requires a decision before each
consequential action". A tool with a side effect and no such option leaves the call to the model
alone. The paper is cited for that statement and nothing more.

**Real-world consequence:** a call that the model makes, including one steered by text the agent
read, runs without a person or a policy having seen it.

**Why severity is high:** The pack sets high and states no reasoning for it.

**Fix type - code:** pass `requires_approval=True` to the tool decorator, or raise `ApprovalRequired` when the arguments need review, and handle `DeferredToolRequests` in the run loop.

**Confidence 0.4:** the pack's explanation states these limits:

- The name words are send_, notify_, refund_, charge_, pay_, payout_, transfer_, delete_, drop_, destroy_, deploy_, publish_, terminate_, revoke_, truncate_. The pack sets them and states no reasoning for them. A tool with a
  side effect under another name is not seen, and a tool that matches a name word and has no side
  effect is a false positive.
- A toolset built outside the `Agent(...)` call is not read. PYD-003 and PYD-004 report the dangerous call in a tool body; this rule reports the missing decision.
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
- Pydantic AI documentation, Deferred Tools page (ai.pydantic.dev), retrieved 2026-11-27. Cited for the option names and the approval mechanism.
