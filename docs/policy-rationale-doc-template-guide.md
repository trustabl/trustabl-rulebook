# Policy Rationale Doc — Template Guide

Every policy YAML file in this repository requires a paired rationale document at:

```
docs/Policy/<category>/<topic>.md
```

Mirror the YAML directory structure exactly. Create the `.md` at the same time as the YAML — never retroactively.

---

## Template

Copy this verbatim. Fill every section. Delete no sections.

```markdown
# Policy Rationale: <Human-Readable Policy Name>

**Policy ID:** `<policy.id from YAML>`  
**File:** `<category>/<topic>.yaml`  
**Rules:** <comma-separated rule IDs, e.g. CSDK-001, CSDK-002>  
**Severities:** <comma-separated severities matching rule order>  
**Fix types:** <comma-separated fix_type values matching rule order — `config` or `code`>  
**References:** <comma-separated OWASP LLM Top 10:2025 IDs that anchor the rules in an external standard — e.g. LLM01, LLM06>

---

## What this policy covers

One paragraph. Name the specific code patterns this policy targets — what
decorator, what call sites, what parameter shapes. Be concrete enough that
a reader who has not seen the YAML knows exactly what triggers the rules.

---

## Why <topic> is a distinct concern in agent tools

Two to four paragraphs. This is the threat model section — the most
important section. Answer:

- What can go wrong when this gap exists?
- Why is this worse in an agentic system than in a conventional application?
- What is the attacker's path (if security) or the failure path (if reliability)?

Ground every claim in a mechanism, not just an assertion. "This is dangerous"
is not sufficient. "The model retries tool calls on timeout; without an
idempotency key the same charge fires twice" is sufficient.

---

## Rule-by-rule defense

One H3 block per rule in this policy file.

### <RULE-ID> — <rule title> (Severity: <X>, Confidence: <Y>, Fix type: <config|code>)

**What we detect:**  
State the exact predicate(s) in plain language. Name the specific functions,
parameter names, or body strings we look for. A reader should be able to
reconstruct the YAML match block from this description.

**Why it is flaggable:**  
Explain what the detection pattern indicates about the code's behavior. Name
the mechanism of failure, not just the presence of the pattern. Connect the
pattern to the consequence.

**Real-world consequence:**  
Give a concrete example — tool name, attacker input or failure scenario,
outcome. One to three bullet points or a short paragraph. Avoid generic
statements ("this could cause problems"). Name the specific damage.

**Why severity is <X> and not <Y>:**  
Defend the severity level. If it is Critical, explain why no partial
mitigation exists. If it is Medium instead of High, explain the precondition
that lowers the impact. Reviewers will challenge severity — answer preemptively.

**Fix type — <config|code>:**  
State whether the fix requires changing tool/agent source code (`code`) or
can be applied purely through guardrails, hooks, sandbox policies, or agent
constructor parameters without touching tool code (`config`). One sentence
justifying the classification. Config fixes are prioritized in scan output
because they carry lower breakage risk.

**Confidence <Z>:**  
Explain what the confidence gap represents. Name the specific false positive
and false negative scenarios the gap accounts for. If confidence is below
0.80, this section is mandatory.

---

## What this policy does not cover

Bulleted list. Be honest. Name:
- Patterns structurally similar to the detected ones that escape detection.
- Equivalent risks implemented via different APIs or libraries.
- Cases where the fix satisfies the rule but does not eliminate the risk.
- Known false positive scenarios (patterns that fire but are safe).

This section is what makes the doc defensible. A policy with no gaps
documented is a policy that has not been thought through.

---

## Recommendations beyond the fix

Code block showing the correct implementation pattern, followed by a
numbered list of additional hardening steps. The code block should show
the full safe version of the tool — not just the one changed line.

The numbered list should name steps that are not detectable by the rule
but materially reduce risk (e.g., "log every write with session_id for
audit", "use is_relative_to() not string prefix matching").
```

---

## Section-by-section rules

### Title and metadata block

- Policy ID must match `policy.id` in the YAML exactly.
- File path is relative to the repo root.
- Rules list in ascending ID order.
- Severities in the same order as the Rules list.
- Fix types in the same order as the Rules list. Allowed values: `config`, `code`.
  - `config` — fix by adding guardrails, hooks, sandbox policies, or agent constructor
    parameters. No tool source code needs to change. These findings appear first in
    scan output.
  - `code` — fix requires modifying tool or agent source code.

### "What this policy covers" — do not skip

This section is how a reader orients before reading the threat model. If
you skip it, reviewers must read the YAML to understand context.

### "Why this is a distinct concern" — the most important section

This is the document's value. A rule without a threat model is just a
linter check. Defend why the pattern matters *in the agent context
specifically*. Every rule category has an agent-specific angle:

| Category | Agent-specific angle |
|----------|---------------------|
| claude_sdk / openai_sdk | Model uses name/desc/schema to route; gaps cause mis-selection or hallucinated args |
| openshell | Tools run in a process with real FS/network access; no browser sandbox |
| mcp | Invoked by external orchestrators with fully model-controlled inputs |
| catalog | Capability class risk is framework-independent; same guard required everywhere |

### "Rule-by-rule defense" — defend the confidence number

Confidence calibration is one of the hardest product decisions in a linter.
Always explain the gap. Common reasons:

| Confidence gap | Common cause |
|---|---|
| Body text search misses imported guards | Function calls guard logic in another module |
| Parameter name heuristic | Pattern fires on `path` that is not a filesystem path |
| Dead code | `raise` statement is unreachable in practice |
| SDK-level mitigation | Library handles the concern transparently |

### "What this policy does not cover" — be adversarial

Write this section as if you are a developer trying to argue the finding
is a false positive. Name the specific patterns that would evade detection.
If you cannot name any, you have not thought hard enough.

### "Recommendations beyond the fix" — show the safe pattern

The code block must show a complete, runnable function — not a snippet.
Use real library names (`stripe.Invoice.create`, `Path(...).resolve()`).
The numbered list after the code block covers hardening that is outside the
rule's detection scope.

---

## Naming and placement rules

| YAML file | Doc file |
|---|---|
| `claude_sdk/network.yaml` | `docs/Policy/claude_sdk/network.md` |
| `openai_sdk/agent_safety.yaml` | `docs/Policy/openai_sdk/agent_safety.md` |
| `google_adk/tool_definition.yaml` | `docs/Policy/google_adk/tool_definition.md` |
| `mcp/injection.yaml` | `docs/Policy/mcp/injection.md` |

Category subdirectories under `docs/Policy/` mirror the repo root exactly.
If a new category directory is created, create the matching directory in `docs/Policy/`.

---

## Cross-referencing related docs

When a rule duplicates or reinforces a rule from another category, the
lower-priority doc should cross-reference the primary doc rather than repeat
the full rationale:

```markdown
**Read [claude_sdk/path_safety.md](../claude_sdk/path_safety.md) for the full rationale.**
This document covers <SDK>-specific differences only.
```

Use relative paths from the doc's own location.

---

## Existing docs (reference implementations)

These docs are the canonical format examples. Read one before writing a new doc.

| Best for | Doc |
|---|---|
| Security rule (Critical) | [Policy/mcp/injection.md](Policy/mcp/injection.md) |
| Reliability rule with low confidence | [Policy/claude_sdk/idempotency.md](Policy/claude_sdk/idempotency.md) |
| Cross-framework rule | [Policy/catalog/capability_class.md](Policy/catalog/capability_class.md) |
| Agent-scope rule | [Policy/openai_sdk/agent_safety.md](Policy/openai_sdk/agent_safety.md) |
| Cross-reference pattern | [Policy/openai_sdk/tool_definition.md](Policy/openai_sdk/tool_definition.md) |
