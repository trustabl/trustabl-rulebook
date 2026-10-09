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
  - id: RT-006
    severity: high
    confidence: 0.9
    scope: runtime
    fix_type: config
  - id: RT-007
    severity: high
    confidence: 0.9
    scope: runtime
    fix_type: config
  - id: RT-008
    severity: critical
    confidence: 0.9
    scope: runtime
    fix_type: config
references: [LLM06, LLM08]
---

# Policy Rationale: Runtime Conformance

**Policy ID:** `runtime_conformance`  
**File:** `runtime/conformance.yaml`  
**Rules:** RT-001, RT-002, RT-003, RT-004, RT-005, RT-006, RT-007, RT-008  
**Severities:** high, medium, high, low, low, high, high, critical  
**Fix types:** config, config, config, code, config, config, config, config  
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

### RT-006: Action observed under an identity the contract is not bound to (high, 0.9)

**What we detect.** A bound action whose bind status is `binding_mismatch`
(`action_status_is: binding_mismatch`): the contract was resolved by its
span-carried hash and carries an identity binding (`trustabl contract bind`
fused it to one canonical principal and one declared workload), and the
span's identity keys (`trustabl.principal.id`, `trustabl.workload.id`,
`trustabl.binding.id`) disagree with that binding. The runtime compares only
after a key-resolved join; a span with no identity keys is recorded as an
unverified binding, not as a mismatch, and a contract nobody bound has
nothing to compare against.

**Why it is flaggable.** The contract's ceilings were compiled for a named
principal: the DSPM data scope is that person's working set, the tool
allow-list and hosts were narrowed for that deployment. Run under another
identity, every one of those ceilings is applied to somebody the compiler
never considered. That is the identity-fusion failure the sandbox binds
against at creation time, and OpenShell cannot see it from inside the jail
because its policy schema has no principal field; the pre-bind check and this
rule are what make the binding enforceable end to end. LLM06 in its exact
form: agency exercised under an identity that was never granted it.

**Consequence.** An agent inherits a person's dormant entitlements under a
contract compiled to prevent exactly that, or a contract bound to a test
sandbox governs a production one. Either way the contract's evidence chain
(constraint addresses, signed summaries) is describing the wrong principal.

**Severity/confidence defense.** High/0.9: the comparison is exact, on
canonical ids the bind step validated, after a hash-resolved join, so a
mismatch is a measured disagreement between two stated identities rather
than an inference. Not critical, because the runtime observes and escalates
and does not block; the enforcement statement governs.

**What this does not cover.** Name-matched actions (no key, no resolved
binding, already reported as `name_match`); the live `watch` path until it
accepts the index and store; a workload that stamps the correct keys while
running as someone else, which is a credential problem the binding cannot see.
The last gap is what the subject ticket (RT-007, RT-008) closes: the keys are
claims the workload makes about itself, the ticket is the issuer's signature
over the same facts.

---

### RT-007: Required subject ticket not presented (high, 0.9)

**What we detect.** A bound action whose bind status is `ticket_missing`
(`action_status_is: ticket_missing`): the contract the action resolved to
carries an identity binding with `ticket_required` (`trustabl contract bind
--require-ticket`, folded into the binding digest), and the span carried no
`trustabl.ticket.id`. The runtime checks the requirement on every action that
resolves to that binding, whether the contract was joined by hash, by name or
after a hash miss, and whether or not any ticket flag was given: a deployment
that drops its binding line does not escape the requirement by that omission.
The summary counts the failure from the failure the binder recorded, not from
the status, so an action whose off-contract deny stood is still named in
`ticket_failures`, citing the binding constraint the ticket failed (the
action's own verdict keeps citing the allow-list), and the guard carries it as
its own action with that deny and the runtime's join method. This rule matches
on the status alone, so it fires for that action too, beside RT-001.

**Why it is flaggable.** The binding's span keys (`trustabl.principal.id`,
`trustabl.workload.id`, `trustabl.binding.id`) are claims a workload stamps on
itself. The subject ticket is the issuer's signature over the same facts, one
principal, one binding, one workload and one contract version, with an issue
time and an expiry, verified offline with the evidence public key. A contract
that requires the ticket has said that the keys alone are not enough. An
action with no ticket is therefore an action nobody vouched for: the runtime
cannot tell a deployment that forgot the stamp from one that was never issued
a ticket, and it fails closed on both. LLM06: agency exercised under an
identity that was asserted, never proven.

**Consequence.** Every ceiling compiled for the bound principal (the data
scope above all) is applied to a workload whose identity fusion was never
signed off. In practice this is a misconfigured deployment: the ticket was
never issued, or the stamp line was dropped when the workload was rolled.
Either way the evidence chain has a hole at the identity step.

**Severity/confidence defense.** High/0.9: the check is a presence test on a
key the binding demanded, after the contract was resolved, so a missing
ticket is a measured absence rather than an inference; 0.9 rather than 1.0
because a workload that stamps the ticket on a different resource attribute,
or a collector that drops it, reads the same. Not critical: the runtime
observes and escalates, it does not block, and a missing ticket is far more
often a rollout mistake than an attack, which is what makes RT-008 the
critical one.

**What this does not cover.** A ticket that was presented and failed (RT-008);
the live `watch` path, which binds by name and cannot verify a ticket until
it accepts the index and store; a contract whose binding does not require a
ticket, where the keys stand alone and RT-006 is the identity rule.

---

### RT-008: Action ran under an invalid subject ticket (critical, 0.9)

**What we detect.** A bound action whose bind status is `ticket_invalid`
(`action_status_is: ticket_invalid`): a `trustabl.ticket.id` was presented
and the ticket failed a check. The runtime runs the engine's checks in order
and names the first that failed: `unknown_id` (not in the ticket store),
`bad_signature` or `demo_signed` (not from this site's issuer, or signed with
the deterministic demo key on an enforcement path), `policyhash_mismatch` and
`binding_mismatch` (fused to another contract version, principal, binding or
workload), `not_yet_valid` and `expired` (judged at the span's end time, or
`--now` for spans that carry none), `revoked` (by the operator, or by the
directory change feed that `contract directory sync` diffs from the Console's
directory snapshots), `store_unreadable` (a ticket store or revocation list
the runtime could not read) and `malformed` (a span end time or a stamp that
is not a ticket id). As with RT-007 the failure is recorded beside a stronger
verdict rather than replacing it, and this rule fires for that action too.

**Why it is flaggable.** A ticket that verifies says the issuer fused this
principal, this workload and this contract version at a known time and has
not withdrawn it. Every failure reason denies one clause of that sentence. An
expired or revoked ticket means the fusion is no longer vouched for, which is
the whole mechanism by which a deactivated user or a changed group stops an
agent within one TTL without any call to the IdP on the request path. A
policyhash or binding mismatch means the workload presents proof for a
different deployment. A bad signature means the proof did not come from the
issuer at all. LLM06 again, and the difference from RT-007 is that here the
workload presented evidence that is wrong, not none.

**Consequence.** An agent keeps running under a principal the directory has
deactivated, or under a contract version that was promoted away, or with a
forged ticket, and every ceiling compiled for the bound principal is applied
to an identity the issuer does not stand behind. Where RT-007 is usually a
rollout mistake, an invalid ticket is either a stale deployment that must be
re-issued or a live incident.

**Severity/confidence defense.** Critical/0.9: the ticket is verified offline
against the evidence public key, the resolved contract's policyhash, the
binding and an append-only revocation list, so a failure is a measured
disagreement with signed facts, and a revoked or forged ticket is exactly the
condition the ticket exists to catch. 0.9 rather than 1.0 because some of the
reasons describe the verifier's own situation rather than the workload's: a
store the runtime cannot read fails closed by design and is fixed on the
runtime host, a mangled span end time or stamp (`malformed`) is fixed in the
deployment's instrumentation, and `unknown_id` after a prune's retention
window is a replay artefact rather than a live incident. The fix text has a
branch for every reason the runtime emits so those cases are not confused
with a revoked or forged ticket.

**What this does not cover.** A ticket that was never presented (RT-007); the
principal being who the directory says they are, which is the directory's job:
the Console keeps it from the IdP's SCIM push through Ory Polis, and the
change feed the engine diffs from its snapshots is what revokes; a valid ticket presented by a workload
that is not the one it was issued to, when the workload id was fused unattested
(the summary's `tickets_unattested` count names how many verified tickets
fused only the name, on actions of any status, and
`tickets_contract_unchecked` how many verified against the binding alone
because no join index gave the runtime a live hash to compare the policyhash
against); pruned history, since a replayed trace older than the store's
retention window finds no ticket and reads `unknown_id`, where inside the
window it read the verdict it gave when live.

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
