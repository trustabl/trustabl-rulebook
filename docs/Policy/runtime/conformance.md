---
policy_id: runtime_conformance
category: runtime
topic: conformance
rules:
  - id: RT-001
    severity: high
    confidence: 0.9
    scope: runtime
    fix_type: config
  - id: RT-002
    severity: medium
    confidence: 0.8
    scope: runtime
    fix_type: config
  - id: RT-003
    severity: high
    confidence: 0.9
    scope: runtime
    fix_type: config
  - id: RT-004
    severity: low
    confidence: 0.6
    scope: runtime
    fix_type: code
  - id: RT-005
    severity: low
    confidence: 0.6
    scope: runtime
    fix_type: config
references: [LLM06, LLM08]
---

# Policy Rationale: Runtime Conformance

**Policy ID:** `runtime_conformance`  
**File:** `runtime/conformance.yaml`  
**Rules:** RT-001, RT-002, RT-003, RT-004, RT-005  
**Severities:** high, medium, high, low, low  
**Fix types:** config, config, config, code, config  
**References:** LLM06 (Excessive Agency), LLM08 (Vector and Embedding Weaknesses — applied here as trust-in-joins: an inferred join treated as exact)

---

## What this policy covers

The first scope whose input is not a scan artifact. These rules are evaluated
engine-side over the SIGNED conformance summary the runtime monitor writes:
observed tool calls, bound to declared agents, judged against the compiled
contract, with the join method recorded on every action. The pack detects and
reports; nothing in it blocks a call, and no rule text may imply otherwise —
the enforcement statement from the engine's Phase 4 governs this surface.

Every claim these rules make rests on measured ground: the binder and its
failure modes were measured against a committed trace corpus
(trustabl-runtime docs/R1-MEASUREMENT.md), and RT-002's threshold is the
number that measurement named.

---

## Rule-by-rule defense

### RT-001 — Tool call outside the declared contract (high, 0.9)

**What we detect.** A bound action whose bind status is `off_contract`:
the agent was resolved with confidence, the tool was judged against the
agent's declared allow-list, and the allow-list refused it
(`action_status_is: [off_contract]`).

**Why it is flaggable.** This is Excessive Agency (LLM06) observed in the
act rather than predicted from source: the agent exercised authority nobody
declared. The binder's collision and partial-confidence handling make this a
strong claim — an ambiguous name or a partial contract is REFUSED into other
statuses, never folded into this one, so an off-contract finding is not a
binding artifact.

**Severity defense.** High, not critical: the monitor renders the verdict
while the call still executes (detection, not prevention), so the finding is
an incident signal, not a prevented incident.

**Confidence gap.** 0.9, not 1.0: the allow-list judged is the compile-time
one; a grant added and deployed between summary windows can briefly read as
off-contract against a stale contract (RT-003 fires alongside in that case,
which is the disambiguator).

**What this does not cover.** Actions the binder could not bind (they are
RT-002's population, deliberately separate), and MCP-transport calls, which
carry no agent identity on the wire.

### RT-002 — Unbound rate above the measured threshold (medium, 0.8)

**What we detect.** A summary window whose unbound fraction (unknown agent +
unresolvable tool + ambiguous name collision) is at or above 10%
(`summary_unbound_rate_gte: 10`).

**Why it is flaggable.** Every conformance claim is computed over the BOUND
population. As the unbound fraction grows, off-contract rate and constraint
attribution degrade silently — the classic monitoring failure where the
number stays green because the denominator shrank. Separating binding
failure from policy violation is the pack's founding discipline; this rule
is that discipline enforced.

**Severity/confidence defense.** Medium/0.8: the corpus measurement showed
named-agent instrumented workloads bind at 0%, so a sustained high rate is
almost always a deployment configuration issue (missing binding key,
nameless call-based agents) with a documented fix, not an attack.

**What this does not cover.** WHY the binding failed — the summary's
per-status breakdown carries that; the rule only gates the rate.

### RT-003 — Runtime carries a contract hash matching no stored contract (high, 0.9)

**What we detect.** Any bound action stamped with a contract hash that
resolved to nothing in the content-addressed store
(`action_has_hash_miss: true`).

**Why it is flaggable.** The hash is the deployment's claim about which
policy governs it. A hash the site cannot resolve means the workload runs
under a policy version outside the site's retained lifecycle: a stale
deployment, an over-aggressive retention bound, or a stamp from a pipeline
this guard has never seen. The binder degrades to name matching (never
force-fits), so verdicts survive — but the exact-join guarantee, the thing
the key exists to provide, is gone for those actions.

**Severity defense.** High: this is the mechanical Runtime Conformance
Verification signal, and an unverifiable policy lineage on a live workload
is a governance failure even when every action is benign.

**What this does not cover.** Which of the three causes applies; the fix
text routes the operator to both remedies (re-stamp, or raise retention).

### RT-004 — Guardrail declared but never observed at runtime (low, 0.6)

**What we detect.** A window against a contract that declares input/output
guardrails, with zero runtime observations of any guardrail executing
(`summary_guards_never_observed: true`).

**Why it is flaggable.** A declared control that leaves no runtime trace
cannot be shown to have operated — the exact class of claim an auditor
refuses on declaration alone. Today the absence is EXPECTED (no ingest
convention extracts guardrail spans yet), and the rule is honest about
that: it fires at low confidence and reports the observability gap itself.

**Severity/confidence defense.** Low/0.6 by design: firing loudly on an
ecosystem-wide instrumentation gap would train operators to ignore the
pack. The rule exists so the gap is RECORDED per deployment rather than
discovered at audit; its confidence rises when guardrail span extraction
lands and absence becomes signal rather than default.

**What this does not cover.** Guardrail effectiveness — only presence of
execution evidence.

### RT-005 — Declared constraint never exercised in the window (low, 0.6)

**What we detect.** At least one compiled constraint id that no observed
action exercised across the window (`summary_constraint_never_hit: true`).

**Why it is flaggable.** An unexercised constraint means the authority it
fences was either unused (a least-privilege review candidate — the
over-grant this surfaces is LLM06's quiet form) or unobserved. Either way
the constraint is unverified in practice, and the compile-to-runtime loop
this scope exists to close has a gap at exactly that address.

**Severity/confidence defense.** Low/0.6: a short window legitimately
leaves constraints unexercised; the fix text says to extend the window
before concluding anything. This is review input, not an alarm.

**What this does not cover.** Which constraint (the finding counts; the
summary's hit list names them), and windows are per-summary — no
cross-window accumulation yet.

---

## Known gaps, stated

- The scope's evaluation host is the guard, not the scanner: these rules
  never fire on a scan, and a site that runs no runtime monitor never
  produces their input. META-005 handles older engines (they skip the pack's
  runtime rules via forward-compatible loading).
- Guardrail observation (RT-004) is currently a recorded absence
  everywhere; the rule's value inverts when extraction lands.
- No rule here claims to block anything. The monitor detects while the call
  executes; the enforcement statement governs every consumer of these
  findings.
