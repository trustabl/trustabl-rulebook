---
policy_id: mcp_elicitation
category: mcp
topic: elicitation
rules:
  - id: MCP-212
    severity: high
    confidence: 0.5
    scope: tool
    fix_type: code
  - id: MCP-214
    severity: high
    confidence: 0.5
    scope: tool
    fix_type: code
references: [LLM06]
---

# Policy Rationale: MCP Tools That Request Elicitation Without Checking the Answer

**Policy ID:** `mcp_elicitation`  
**File:** `mcp/elicitation.yaml`  
**Rules:** MCP-212, MCP-214  
**Severities:** high, high  
**Fix types:** code, code  
**References:** OWASP LLM Top 10:2025 — LLM06 (Excessive Agency)

> **Verification status.** The advisory and the MCP specification page (version 2025-06-18) were read on 2026-11-25 as raw page text. The NVD record for CVE-2026-115477 was not read. **Not verified, and therefore not assumed:** how SDK versions after 2025-06-18 shape the elicitation result; that the tools flagged here have a side effect, which the rules do not check; and whether any flagged server has the advisory's flaw.

---

## What this policy covers

MCP elicitation lets a tool handler ask the person for input through the client. **MCP-212** (Python, `elicit(`) and **MCP-214** (TypeScript, `elicitInput` or `elicitation/create`) flag a handler whose body contains no `accept` or `Accept` anywhere. MCP-030 credits a handler that calls `elicit(` as a gate; these rules read whether the answer is tested.

---

## Rule-by-rule defense

### MCP-212 — MCP tool requests elicitation but does not check for an accept action (Severity: high, Confidence: 0.5, Fix type: code)

**What we detect:** `has_body_text` finds `elicit(` in the handler body and finds neither `accept` nor `Accept`. Applies to Python `mcp_tool`.

**Why it is flaggable.** The MCP specification's elicitation page says responses "use a three-action model": `accept`, `decline` and `cancel`, and says "Servers should handle each state appropriately". GitHub advisory GHSA-737x-cwfr-5vvc (obsidian-tc, CVE-2026-115477) states: "a destructive: true tool call, offered inputRequired, answered with {action: "decline"} on the elicitation/create leg, still wrote." The fix it describes requires the response "to be {action: "accept", content: {approve: true}} before trusting the echoed state". The advisory is cited for those statements and nothing more. It concerns a different mechanism (an echoed request state in one server) from a handler that ignores the result.

**Real-world consequence:** a handler that continues after any answer treats a decline or a cancel as approval.

**Why severity is high:** The pack sets high and states no reasoning for it.

**Fix type — code:** the fix is an edit to the handler. The pack's fix keeps the result and proceeds when the action equals `accept`.

**Confidence 0.5:** the pack's explanation states these limits of the check:

- It reads the handler body as text, does not follow the answer into a helper, and does not judge whether the tool has a side effect.
- A mention of `accept` in a comment or a string counts as a check, and an `elicit(` call that appears in a comment and nowhere else counts as a call.
- An elicit call in another function or file is not seen.

**Field check, run on 2026-11-25** (prototype of the detector over cloned public repositories at the commits listed in the report `~/trustabl-reports/static-batch-3.md`; not a random sample). Before the side-effect condition was added, the rule produced 19 findings in 2 repositories (16 in `PrefectHQ/fastmcp` and 3 in `modelcontextprotocol/python-sdk`, all under test paths) in the Python sample. Each was a test tool that elicits and has no side effect, which is not a risk; all 19 were judged false positives. With the condition (a shell, code-execution or file-write call in the body), the same repositories produce 0 findings. The rule found no true positive in the field sample, so recall rests on the unit tests and the corpus fixture.

### MCP-214 — TypeScript MCP tool requests elicitation but does not check for an accept action (Severity: high, Confidence: 0.5, Fix type: code)

**What we detect:** `has_body_text` finds `elicitInput` or `elicitation/create` in the handler source span and finds neither `accept` nor `Accept`. Applies to TypeScript and JavaScript `mcp_tool`.

**Why it is flaggable.** The same two sources as MCP-212, cited for the same statements.

**Real-world consequence:** as for MCP-212.

**Why severity is high:** The pack sets high and states no reasoning for it.

**Fix type — code:** an edit to the handler.

**Confidence 0.5:** the pack's explanation states these limits of the check:

- It reads the handler source span as text, does not follow the answer into a helper, and does not judge whether the tool has a side effect.
- A mention of `accept` in a comment or a string counts as a check, and an `elicitInput` call that appears in a comment and nowhere else counts as a call.

**Field check, run on 2026-11-25** (prototype of the detector over cloned public repositories at the commits listed in the report `~/trustabl-reports/static-batch-3.md`; not a random sample). Before the side-effect condition was added, the rule produced 3 findings in 1 repository (`cloudflare/agents`, a conformance server, `test_elicitation` tools with no side effect); all 3 were judged false positives. With the condition, 0 findings. The TypeScript sample (3 to 4 repositories that call `elicitInput` or `elicitation/create`) is small.

---

## What this policy does not cover

- Whether the tool has a side effect, and whether the check sits before it.
- A check of the answer in a helper function or another file.
- Binding an accept to the arguments of the call it approves.
- Servers that fall back to a model-settable flag when the client cannot elicit.

---

## Recommendations beyond the fix

1. Keep the elicit result and compare its action to `accept` in the handler that holds the side effect.
2. Return or raise on `decline` and `cancel`.
3. Test the decline and cancel paths.

---

## Sources

- Model Context Protocol specification 2025-06-18, Elicitation: https://modelcontextprotocol.io/specification/2025-06-18/client/elicitation Retrieved 2026-11-25. Cited for the three response actions and the sentence on handling each state, and nothing more.
- GitHub advisory GHSA-737x-cwfr-5vvc: https://github.com/advisories/GHSA-737x-cwfr-5vvc Retrieved 2026-11-25. Cited for the decline-then-write report and the accept requirement in the fix, and nothing more.
