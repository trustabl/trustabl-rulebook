---
policy_id: google_adk_consequential_tool_gate
category: google_adk
topic: consequential_tool_gate
rules:
  - id: ADK-204
    severity: high
    confidence: 0.4
    scope: agent
    fix_type: code
references: [LLM06]
---

# Policy Rationale: Google ADK Agent With a Side-Effecting Tool and No Approval

**Policy ID:** `google_adk_consequential_tool_gate`  
**File:** `google_adk/consequential_tool_gate.yaml`  
**Rules:** ADK-204  
**Severities:** high  
**Fix types:** code  
**References:** LLM06

> **Verification status.** The paper cited below was read on 2026-11-27 as the abstract on its
> arXiv page. The SDK pages named in Sources were retrieved on 2026-11-27 and the quotations in
> the rule come from them. **Not verified, and therefore not assumed:** that the paper's attacks
> work against Google ADK; that a tool with one of the name words below changes anything outside
> the process; what share of repos have such a tool without a gate.

---

## What this policy covers

This policy has one rule. **ADK-204** is agent scope. It reads the agent's constructor call and the
tools resolved from its tools list, and reports an agent that holds a tool with a side effect and
shows no decision point before the call. It reports one finding for each agent, attributed to the
constructor call. The pack loads when the repo imports Google ADK.

---

## Rule-by-rule defense

### ADK-204 - Agent holds a side-effecting tool with no confirmation or before_tool_callback (Severity: high, Confidence: 0.4, Fix type: code)

**What we detect:** an agent, gated by `agent_consequential_tool_ungated`, that holds a tool with
a name that starts with one of the name words, or a body that runs a subprocess, evaluates code or writes a file, and no gate. The gates read are `require_confirmation` on `FunctionTool` (a value other than `False`), a `request_confirmation` call in the tool body, and a `before_tool_callback` kwarg on the agent (any value but `None`).

**Why it is flaggable.** The Google ADK Tool Confirmation page describes a feature that lets a tool "pause its execution" for a confirmation, and the callbacks page states that when `before_tool_callback` returns a dictionary, "the tool's run_async method is skipped". *Blocking at the Boundary* (arXiv 2610.05163, submitted 4
October 2026) states in its abstract that "Stopping such attacks requires a decision before each
consequential action". A tool with a side effect and no such option leaves the call to the model
alone. The paper is cited for that statement and nothing more.

**Real-world consequence:** a call that the model makes, including one steered by text the agent
read, runs without a person or a policy having seen it.

**Why severity is high:** The pack sets high and states no reasoning for it.

**Fix type - code:** pass `require_confirmation=True` to `FunctionTool`, call `tool_context.request_confirmation(...)` in the tool, or set a `before_tool_callback` that checks the tool name and arguments against a policy.

**Confidence 0.4:** the pack's explanation states these limits:

- The name words are send_, notify_, refund_, charge_, pay_, payout_, transfer_, delete_, drop_, destroy_, deploy_, publish_, terminate_, revoke_, truncate_. The pack sets them and states no reasoning for them. A tool with a
  side effect under another name is not seen, and a tool that matches a name word and has no side
  effect is a false positive.
- A plugin registered on the runner is not read. A bare function in `tools=[...]` is not discovered as an ADK tool. ADK-020 and ADK-021 report a narrower case and can report the same agent.
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
- Google ADK documentation, Tool Confirmation and Callbacks pages (google.github.io/adk-docs), retrieved 2026-11-27. Cited for the option names and the quoted sentences.
