---
policy_id: agent_config_guard_warn_only
category: agent_config
topic: guard_warn_only
rules:
  - id: AGCFG-020
    severity: medium
    confidence: 0.5
    scope: repo
    fix_type: code
references: [LLM06]
---

# Policy Rationale: Security Guard Set to Log Instead of Block

**Policy ID:** `agent_config_guard_warn_only`  
**File:** `agent_config/guard_warn_only.yaml`  
**Rules:** AGCFG-020  
**Severities:** medium  
**Fix types:** code  
**References:** LLM06 (Excessive Agency)

> **Verification status.** The advisory text below was read on 2026-11-26 from the GitHub
> Advisory Database record for GHSA-j8f7-x8jm-wmm4 (Langflow). Two other advisories that
> the source sheet lists for this rule were read the same day and are not relied on:
> GHSA-fj8f-m44g-c479 (PraisonAI) describes a block threshold whose default is `CRITICAL`,
> not a warn flag, and GHSA-w7x8-q2gp-5cgg (Flowise) describes a validator bypass. The
> sheet's source cell lists more advisories than these three; these three were the ones available to read. **Not
> verified, and therefore not assumed:** the code of any Langflow release beyond what the
> advisory quotes, and whether other projects use the same keyword names.

---

## What this policy covers

A request guard can be configured to log what it would block. This policy has one rule.
**AGCFG-020** flags a literal keyword at a call that puts an SSRF guard in that mode or
turns it off. It is repo scope and reports one finding per matching call. The pack loads for
each scan, because the file has no SDK import; the rule's own predicate does the gating.

---

## Rule-by-rule defense

### AGCFG-020 — SSRF guard is called in logging mode or switched off by a literal (Severity: medium, Confidence: 0.5, Fix type: code)

**What we detect:** a Python call whose name contains `ssrf` and that passes
`warn_only=True`, or any Python call that passes `ssrf_protection_enabled=False`. Gated by
`repo_call_kwarg_matches`.

What is not flagged: `warn_only=False`; `ssrf_protection_enabled=True`; `warn_only=True` on
a call whose name does not contain `ssrf` (the keyword name belongs to unrelated
libraries); a value from a variable, a configuration file or an environment variable; a
default value in a function definition; a setting assigned as an attribute; other guard
keywords and mode strings; TypeScript code; and files under a test path.

**Why it is flaggable.** GHSA-j8f7-x8jm-wmm4 states that before Langflow 1.10.3 the SSRF
guard "shipped with `ssrf_protection_enabled = False`" and that its caller, the API Request
component, called `validate_url_for_ssrf(url, warn_only=True)`, so that with protection
turned on a blocked URL was logged and not refused. It states that a user who could build
or run flows could reach loopback, private-network, link-local and cloud-metadata
addresses, and in many cases read the response through the component output.

**Real-world consequence:** a request to an internal address is recorded and then sent.

**The same pattern, observed.** In the public sample for this batch, the Langflow tag
`1.9.2` contains `validate_url_for_ssrf(url, warn_only=True)` in the API Request component,
which the rule flags.

**Why severity is medium:** The pack sets medium and states no reasoning for it. The check does not read whether the agent
also holds execution, egress or payment tools, where a higher severity could be argued.

**Fix type — code:** the fix edits the call. The pack's fix is to remove `warn_only=True`,
set `ssrf_protection_enabled` to `True`, and confine any logging period to a staging
configuration.

**Confidence 0.5:** the pack's explanation states these limits of the check:

- It reads the literal keyword at the call; a mode set through a variable, a configuration
  file, an environment variable or a class attribute is not judged, and a default in a
  function definition is not a call.
- `warn_only` is judged on a call whose name contains `ssrf` and on no other call;
  `ssrf_protection_enabled` is judged on any call.
- Other guard keywords and mode strings such as `monitor` or `audit` are not judged, and
  the check does not know whether a second guard blocks the same request.
- Files under a test path are not read, and TypeScript is not read.

The pack states no other limits for this rule.

---

## What this policy does not cover

- Guards that block by default and are weakened through a threshold, such as the PraisonAI
  block threshold.
- Guard modes set outside a call keyword.
- Guards that are absent, and URL-taking code that does not call a guard.

---

## Recommendations beyond the fix

1. Keep the committed call blocking; measure a logging period in a staging configuration.
2. Apply the guard to each component that takes a URL.

---

## Sources

Retrieved 2026-11-26.

- GitHub Advisory Database, GHSA-j8f7-x8jm-wmm4, "Langflow: SSRF in URL-taking components ...". Cited for the `warn_only=True` call and
  the `ssrf_protection_enabled = False` default, and nothing more.
