---
policy_id: crewai_approval_token_tools
category: crewai
topic: approval_token_tools
rules:
  - id: CREW-203
    severity: high
    confidence: 0.4
    scope: agent
    fix_type: code
references: [LLM06]
---

# Policy Rationale: CrewAI Agent That Can Request and Redeem an Approval Token

**Policy ID:** `crewai_approval_token_tools`  
**File:** `crewai/approval_token_tools.yaml`  
**Rules:** CREW-203  
**Severities:** high  
**Fix types:** code  
**References:** OWASP LLM Top 10:2025 — LLM06 (Excessive Agency)

> **Verification status.** arXiv 2610.23077 was read on 2026-11-26 as raw page text. arXiv 2610.22899 names none of the parameters and is not cited. **Not verified, and therefore not assumed:** that a tool named like an approval request is an approval service; that any parameter name other than `authorized_by` carries an approval token; and how many agents in public repositories hold such a pair.

---

## What this policy covers

**CREW-203** reads the agent's `tools` list and flags an agent that holds a tool taking an `authorized_by` parameter and a different tool whose name asks for an approval or access grant.

---

## Rule-by-rule defense

### CREW-203 — Agent holds a tool taking authorized_by and a tool that requests an approval (Severity: high, Confidence: 0.4, Fix type: code)

**What we detect:** `agent_tools_match` with `param_names: [authorized_by]` and `other_tool_name_regex` matching `request`, `obtain`, `issue`, `create` or `grant` followed by `approval` or `access` in underscore form. Applies to `crewai_agent`.

**Why it is flaggable.** The paper "When Approval Becomes Execution" (arXiv 2610.23077) describes a workflow in which "the agent requests a normal approval token from the local approval service, and the returned token is supplied to the document service through authorized_by", reports 9/9 token transitions and 8/9 exact completions in its original configuration, and gives as an untested mitigation that "protected services should not treat token possession through a stand-alone field such as authorized_by as sufficient". The paper is cited for those statements and nothing more. It does not use any other parameter name, and it does not propose a name-based static rule; the tool-name pattern is the rule's.

**Real-world consequence:** an agent that is induced to request an approval can pass the returned token to the protected tool and complete the operation.

**Why severity is high:** The pack sets high and states no reasoning for it.

**Fix type — code:** the fix binds the approval to the requester and the action on the service side, and removes or gates the approval-requesting tool.

**Confidence 0.4:** the pack's explanation states these limits of the check:

- The paper names `authorized_by`; no other parameter name is read.
- The second tool's name is matched against a pattern chosen for the rule after camel case is split; the paper does not state that such a tool is an approval service and does not recommend separating the two tools.
- Tools must resolve to a definition in the scanned code (a reference written as one wrapper call around a name, such as `Tool(fn)`, is looked up in the same file); what the tools do is not read.
- In the paper's scenario the request named another user as approver; the rule does not read that. A tool taking `authorized_by` with an unrelated meaning is reported.

**Field check, run on 2026-11-26** (prototype of the detector over cloned public repositories at the commits listed in the report `~/trustabl-reports/static-batch-2.md`; not a random sample; each repository was scanned once, with a 120 second cap). Sample: 3 CrewAI repositories were scanned (`maximem-ai/maximem_synap_sdk` e2df479, `headroomlabs-ai/headroom` 98ba445, `yaalalabs/agent-kernel` 7c7e61e). 0 hits. **Small sample.**


---

## What this policy does not cover

- Parameter names other than `authorized_by`.
- Agents whose tools are defined in another module.

---

## Recommendations beyond the fix

1. Bind approvals to the requester, approver, resource and action on the service side.
2. Require a person to approve the second call.

---

## Sources

- "When Approval Becomes Execution: Authorization-Grounded Workflow Attacks on Tool-Using Agents", arXiv 2610.23077: https://arxiv.org/abs/2610.23077 Retrieved 2026-11-26. Cited for the attack description, the `authorized_by` parameter, the reported counts and the stated mitigation, and nothing more.
