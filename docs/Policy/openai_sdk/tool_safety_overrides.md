---
policy_id: openai_sdk_tool_safety_overrides
category: openai_sdk
topic: tool_safety_overrides
rules:
  - id: OAI-208
    severity: high
    confidence: 0.5
    scope: tool
    fix_type: code
  - id: OAI-209
    severity: high
    confidence: 0.5
    scope: tool
    fix_type: code
references: [LLM06]
---

# Policy Rationale: OpenAI Agents SDK Tools With Model-Settable Overrides and Unbounded Orders

**Policy ID:** `openai_sdk_tool_safety_overrides`  
**File:** `openai_sdk/tool_safety_overrides.yaml`  
**Rules:** OAI-208, OAI-209  
**Severities:** high, high  
**Fix types:** code, code  
**References:** OWASP LLM Top 10:2025 — LLM06 (Excessive Agency)

> **Verification status.** The advisory GHSA-qjx4-hg6g-2f34 was read on 2026-11-25 from the repository security-advisory page of `strands-agents/tools`; the `github.com/advisories` page for it returned "Not Found". The arXiv abstract page was read on the same date. The NVD pages for CVE-2026-77931 and CVE-2026-76066 were not reachable and are not cited. **Not verified, and therefore not assumed:** that the parameter names the rule lists match the parameters in those two CVEs; that the advisory's own parameter (`masked`) is matched, which it is not; and the paper's per-system results beyond the three counts quoted.

---

## What this policy covers

**OAI-208** flags a `@function_tool` that reaches a shell, code-execution or file-write call and takes a parameter named like a safety override. **OAI-209** flags an options order tool that takes strike, expiry or legs, with no limit word in its body and no `needs_approval` gate. The OpenAI Agents SDK pack is the one built; the same checks for other SDK packs are not.

---

## Rule-by-rule defense

### OAI-208 — Tool that reaches shell, code or write calls takes a model-settable override parameter (Severity: high, Confidence: 0.5, Fix type: code)

**What we detect:** `param_name_matches` with exact names `confirm`, `confirmed`, `force`, `unsafe`, `allow_dangerous`, `no_confirm` or prefixes `confirm_`, `bypass_`, `dangerously_`, `skip_confirm`, `skip_check`, `skip_valid`, `skip_safety`, `skip_approval`, together with `has_shell_call`, `has_code_exec_call` or `has_write_call`. Applies to Python `openai_tool`.

**Why it is flaggable.** GitHub advisory GHSA-qjx4-hg6g-2f34 (strands-agents-tools) states: "The masked parameter that controls this behavior was declared in the tool's input schema, so the large language model (LLM) could set it." It describes an actor who places instructions in content the agent processes and directs the model to call the tool with `masked=false`, which returned environment variables unmasked, and a fix in which masking is controlled by the operator and the model cannot disable it. The advisory is cited for those statements and nothing more. Its parameter is not on the rule's list and its tool has no shell, code or write call, so the advisory shows the problem class and not a case the rule matches.

**Real-world consequence:** text that steers the model can set the flag, and the tool then skips the check the flag controls.

**Why severity is high:** The pack sets high and states no reasoning for it.

**Fix type — code:** remove the parameter from the schema and gate the tool with `needs_approval=True`.

**Confidence 0.5:** the pack's explanation states these limits of the check:

- It reads parameter names and the presence of a sink call; it does not check that the body uses the parameter to skip anything, so a `force` flag that changes how a file is overwritten matches.
- A differently named override, a string or enum parameter, and a sink reached through a helper are not matched.

**Field check, run on 2026-11-25** (prototype of the detector over cloned public repositories at the commits listed in the report `~/trustabl-reports/static-batch-3.md`; not a random sample). 10 repositories with `@function_tool` Python tools (541 tools): 0 findings. Recall rests on the unit tests and the corpus fixture.

### OAI-209 — Options order tool has no loss or size limit and no approval gate (Severity: high, Confidence: 0.5, Fix type: code)

**What we detect:** a tool name starting `place_order`, `submit_order`, `place_option`, `buy_`, `sell_`, `trade_` or `open_position`; a parameter containing `strike` or `expir`, or named `legs`; a body with none of `max_loss`, `MAX_LOSS`, `max_notional`, `MAX_NOTIONAL`, `notional_limit`, `risk_limit`, `RISK_LIMIT`, `defined_risk`; and no `needs_approval` argument, or `needs_approval=False`. Applies to Python `openai_tool`.

**Why it is flaggable.** Wang and Saxena, *Unbounded Losses, Unchecked Inputs: Measuring the Safeguards of LLM Options-Trading Agents* (arXiv 2610.24289), score 26 systems and report: "Of the 22 systems that can place orders, 10 enforce a pre-trade limit outside the model" and "Of the 26, 17 can execute with no mandatory human step and 13 can reach unbounded loss". The paper is cited for those counts and nothing more.

**Real-world consequence:** the model chooses strike, expiry and legs, and no code limits the loss of the order.

**Why severity is high:** The pack sets high and states no reasoning for it.

**Fix type — code:** check the order against a limit held outside the model's control, and set `needs_approval=True`.

**Confidence 0.5:** the pack's explanation states these limits of the check:

- It reads names, a fixed list of limit words and the decorator; a limit in a helper, a broker client or another module is not seen.
- An order action with another name, and a tool with no strike, expiry or legs parameter, are not judged.
- It does not check whether a short leg can be reached.

**Field check, run on 2026-11-25** (prototype of the detector over cloned public repositories at the commits listed in the report `~/trustabl-reports/static-batch-3.md`; not a random sample). The same 10 repositories (541 tools) and 6 public options-trading repositories (none of which uses the OpenAI Agents SDK `@function_tool`): 0 findings. **No public options-trading tool of this shape was found**, so the rule's real-world behavior is untested; recall rests on the unit tests and the corpus fixture.

---

## What this policy does not cover

- The same checks in other SDK packs (MCP, Claude SDK, LangChain, Google ADK).
- Override names outside the list, and what the body does with the parameter.
- Equity and crypto order tools, and limits enforced outside the tool.

---

## Recommendations beyond the fix

1. Keep confirmation and limits in the application that runs the agent.
2. Set `needs_approval=True` on tools that run commands, write files or place orders.
3. Test the tool with a model-chosen value for each parameter.

---

## Sources

- GitHub advisory GHSA-qjx4-hg6g-2f34 (strands-agents/tools): https://github.com/strands-agents/tools/security/advisories/GHSA-qjx4-hg6g-2f34 Retrieved 2026-11-25. Cited for the statements quoted above, and nothing more.
- arXiv 2610.24289, abstract page: https://arxiv.org/abs/2610.24289 Retrieved 2026-11-25. Cited for the three counts quoted above, and nothing more.
