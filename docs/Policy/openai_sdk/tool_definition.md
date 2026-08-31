---
policy_id: openai_sdk_tool_definition
category: openai_sdk
topic: tool_definition
rules:
  - id: OAI-001
    severity: low
    confidence: 0.9
    scope: tool
    fix_type: code
  - id: OAI-002
    severity: medium
    confidence: 0.85
    scope: tool
    fix_type: code
  - id: OAI-007
    severity: low
    confidence: 0.9
    scope: tool
    fix_type: code
  - id: OAI-022
    severity: low
    confidence: 0.85
    scope: tool
    fix_type: code
  - id: OAI-025
    severity: low
    confidence: 0.5
    scope: tool
    fix_type: code
references: [LLM06]
---

# Policy Rationale: Tool Definition Hygiene

**Policy ID:** `openai_sdk_tool_definition`  
**File:** `openai_sdk/tool_definition.yaml`  
**Rules:** OAI-001, OAI-002, OAI-007, OAI-022, OAI-025  
**Severities:** low, medium, low, low, low  
**Fix types:** code, code, code, code, code  
**References:** LLM06

> **Read [claude_sdk/tool_definition.md](../claude_sdk/tool_definition.md) for the full threat model.**
> This document covers OpenAI Agents SDK–specific differences only.

---

## What this policy covers

OpenAI Agents SDK `@function_tool`-decorated functions whose model-facing
interface is underspecified: OAI-001 fires on a missing docstring
(`has_docstring: false`), OAI-002 on no type-annotated parameters
(`has_typed_params: false`), OAI-007 on a vague name (`name_in`), OAI-022 on a
TypeScript `tool({...})` with an empty `description`. Same predicates and same
routing rationale as the Claude tool-definition policy. One rule is different in
kind: OAI-025 does not read the tool's interface at all — it reads the engine's
call-graph liveness verdict (`reachability_is: [unreachable]`) and fires on a
Python tool whose name is referenced nowhere in the repo, i.e. dead capability
code that no agent wires and no model can call today.

---

## Why tool-definition hygiene is a distinct concern in agent tools

The mechanism is identical to the Claude case — the model routes on the tool's
name, description, and parameter schema, and gaps cause mis-selection or
fabricated arguments. See
[claude_sdk/tool_definition.md](../claude_sdk/tool_definition.md#why-tool-definition-hygiene-is-a-distinct-concern-in-agent-tools).

OpenAI-specific note: `@function_tool` builds the tool's JSON schema from the
type hints and docstring automatically, and by default enforces it in
`strict_mode`. So untyped parameters (OAI-002) not only loosen the model's
guidance, they weaken the very schema strict-mode would otherwise enforce — this
policy pairs with `decorator_config` (OAI-003, which flags `strict_mode=False`).

OAI-025 adds a concern the interface-hygiene rules cannot express: capability
that exists but is wired to nothing. A `@function_tool` definition is not inert
prose — it is a callable with a model-facing schema, and in practice it often
touches the filesystem, network, or a subprocess. When no `Agent(tools=[...])`,
no handoff, and no call site references it, that capability sits in the tree
outside the review pressure live tools receive: nobody exercises it, nobody
re-audits it when its dependencies change, and nothing stops a later refactor
from wiring it into an agent in a single line. OWASP LLM06 (Excessive Agency)
names removing unneeded tools as the first mitigation; a defined-but-unwired
tool is the purest form of a tool that is not needed. The rule exists so that
dead capability is either deleted or wired in deliberately — not left to drift
until someone re-exposes it without review.

---

## Rule-by-rule defense

### OAI-001 — Tool function has no docstring (Severity: low, Confidence: 0.9, Fix type: code)
**What we detect:** A `@function_tool` with no docstring. **Why it is flaggable:**
the SDK uses the docstring as the model-facing description; without it the model
routes on the name alone. **Real-world consequence:** two similar tools become
indistinguishable to the router, so the wrong one fires under an ambiguous
prompt. **Why low not medium:** degrades selection, rarely direct harm.
**Fix type — code:** add a docstring. **Confidence 0.9:** rare false positive
where the description is set via a decorator kwarg.

### OAI-002 — Tool has no type-annotated parameters (Severity: medium, Confidence: 0.85, Fix type: code)
**What we detect:** a tool with parameters, none annotated. **Why it is
flaggable:** the type hints become the enforced JSON schema; without them the
model fabricates loosely-typed arguments. **Real-world consequence:**
`transfer(amount, to)` runs with `amount="a lot"`. **Why medium not low:**
wrong-argument execution, not just mis-selection. **Fix type — code:** annotate
the parameters. **Confidence 0.85:** a tool whose schema comes from a Pydantic
model elsewhere can be a false positive.

### OAI-007 — Ambiguous tool name (Severity: low, Confidence: 0.9, Fix type: code)
**What we detect:** a name in the vague-verb set (`process`, `run`, `handle`, …).
**Why it is flaggable:** a generic name carries no routing signal. **Real-world
consequence:** `run` and `process` are a coin-flip for the router. **Why low not
medium:** a clear docstring compensates. **Fix type — code:** rename to
verb-noun. **Confidence 0.9:** curated name list, deliberate matches.

### OAI-022 — TypeScript tool has no description (Severity: low, Confidence: 0.85, Fix type: code)

**What we detect:**
A TypeScript `tool({...})` whose `description` option is empty
(`has_docstring: false`). Discovery sets the tool's `Description` only when the
`description` key's value is a string literal (`ExprLiteralString`); `PredHasDocstring`
is `TrimSpace(Description) != ""`. So an omitted/empty `description` **and** a
`description` built from a non-literal expression (a template string, an
identifier, a concatenation) are both captured as empty and fire. Unlike the
Python sibling OAI-001, which reads the docstring, the TypeScript factory takes the
description as an explicit option.

**Why it is flaggable:**
The SDK sends this `description` to the model as the basis for deciding whether to
call the tool. Empty, the model routes on the tool name alone — the same
mis-selection mechanism as the Python sibling
[OAI-001](#oai-001--tool-function-has-no-docstring-severity-low-confidence-09-fix-type-code).

**Real-world consequence:**
A `tool({ name: "lookup", description: "" , ...})` next to a described `search`
tool is a coin-flip for the router under an ambiguous prompt — the wrong tool
fires.

**Why severity is low and not medium:**
Like OAI-001 it degrades selection but rarely causes direct harm, and the tool name
partially compensates.

**Fix type — code:**
Adding the `description` string in the `tool({...})` options is a tool-source edit.

**Confidence 0.85:**
Matches the Python sibling's 0.85. The firing is mechanically exact, but a
`description` assembled at runtime from a non-literal expression is real text the
model sees yet captured as empty here — the false-positive case the literal-only
capture cannot rule out, which the YAML explanation calls out explicitly.

### OAI-025 — Tool is defined but never referenced anywhere in the repo (Severity: low, Confidence: 0.5, Fix type: code)

**What we detect:**
A Python `@function_tool` whose call-graph liveness state is `unreachable`
(`reachability_is: [unreachable]`). Before detectors run, the engine builds an
intra-repo call graph from every parsed Python file and stamps each Python tool
with a liveness verdict. The verdict is deliberately two-valued in practice:
`unknown` when the tool's name is referenced *anywhere* beyond its own
definition — passed as a value in `tools=[...]`, named in a handoff, called,
aliased, even mentioned by an unrelated same-named identifier — and
`unreachable` **only when the name appears as an identifier nowhere in the
repo's Python source except its own `def` line** (the analyzer never asserts
`reachable` for a tool, because a function handed to a framework as a value is
used but not on a proven call path). Only `unreachable` fires this rule.
A tool with no verdict at all — TypeScript source, or a repo where no call
graph was built — matches nothing: `PredReachabilityIs` treats an empty
liveness state as a non-match, the fail-safe direction.

**Why it is flaggable:**
A tool that nothing references is dead capability code. It is not exposed to
any model today — by construction, no agent's `tools=[...]` carries it — but it
is not inert either: it has a model-facing schema and, typically, real
side-effect capability behind it. The failure mechanism is deferred, in two
directions. Forward: because no agent can call it, no review pressure keeps it
current, and a later refactor can wire the forgotten definition into an agent
in one line — instantly exposing capability that drifted unreviewed for months,
with no diff on the tool itself to draw a reviewer's eye. Sideways: dead
definitions misdirect audit effort — human reviewers and this scanner's own
tool-scope rules spend attention on code no model can invoke, at the expense of
the tools that are actually live.

**Real-world consequence:**
- A `purge_customer_records` tool written for a prototype outlives the
  prototype. Two quarters later a new agent is assembled from "the existing
  utils module" and the tool goes live — a destructive capability nobody has
  looked at since it was orphaned, now one model decision away from executing.
- A security review budgets hours to harden a shell-invoking tool that, unknown
  to the reviewer, no agent references — while a live, reachable tool with the
  same gap goes unexamined.

**Why severity is low and not medium:**
There is no present-tense attack surface. An unreachable tool is invocable by
no agent and no model, so nothing an attacker injects today can reach it — the
harm path requires a *future code change* (the re-wiring) before any input can
flow. Medium would claim a harm that exists now; this rule's claim is strictly
latent: unreviewed drift plus cheap future exposure. That matches the OWASP
LLM06 framing, where unneeded functionality is a hygiene surface to remove, not
an active exposure to contain. The finding is a prompt to decide — delete or
wire in deliberately — not an incident.

**Fix type — code:**
The canonical resolution is deleting the dead tool definition, a tool-source
change. The alternative the fix text offers — wiring it into the intended
agent's `tools=[...]` — is a deliberate design change that *creates* live
capability rather than overlaying a guardrail on existing behavior, so neither
branch qualifies as a config fix.

**Confidence 0.5:**
The lowest confidence in this policy, and it must be: reachability is
best-effort **static, name-level** resolution over the repo's own Python
source, so every form of dynamic or external wiring reads as unreachable while
being genuinely live. The false-positive scenarios the 0.5 prices in:

- **Dynamic dispatch.** `getattr(tools_module, "send_invoice")`, a
  string-keyed registry, or `importlib`-driven loading names the tool only
  inside string literals; the identifier scan sees nothing and a live tool
  fires as dead. The YAML fix text calls this out and asks for a direct name
  reference precisely so both the model wiring and this analysis can track it.
- **Cross-repo and plugin consumers.** A tool exported as a library, or
  exposed through a `pyproject.toml` entry point, is wired by code the scanned
  repo does not contain; an intra-repo graph cannot see the consumer.
- **Framework auto-discovery.** A runtime that walks a module collecting
  `@function_tool`-decorated members at startup never writes the tool's
  identifier anywhere.
- **Parse loss.** A referencing file that fails to parse contributes no
  identifier occurrences, so a tool referenced only there flips to
  unreachable.

The analyzer is conservative in the opposite direction — any identifier
occurrence anywhere in the repo, including an unrelated symbol that happens to
share the name, suppresses the finding as `unknown` — so the rule also
under-fires on genuinely dead tools with common names. Both directions are
structural to name-level liveness, which is why the confidence stays at 0.5 and
the severity at low: together they keep the finding advisory, a request to
confirm intent rather than an assertion of a defect.

---

## What this policy does not cover

Same gaps as [claude_sdk/tool_definition.md](../claude_sdk/tool_definition.md#what-this-policy-does-not-cover):
present-but-misleading descriptions, present-but-too-loose types (`x: Any`),
overlapping tool purposes, and descriptions supplied via decorator kwargs. For
OAI-022 specifically: a TypeScript `description` assembled from a non-literal
expression is real text the model reads, but the literal-only capture records it as
empty and fires anyway.

For OAI-025 specifically:

- **Tools wired but never run.** `Agent(tools=[send_email])` on an agent that
  is itself never executed is `unknown`, not `unreachable` — the rule stays
  silent on capability that is wired into a dead agent, which is arguably the
  same latent risk one level up.
- **Dynamically dispatched tools fire as dead.** String-keyed registries,
  `getattr`, entry points, and framework auto-discovery are live wirings the
  name-level scan cannot see — the rule's dominant false-positive class (see
  the confidence defense above).
- **Same-named symbols mask genuinely dead tools.** Liveness is name-level,
  not symbol-level: any identifier sharing the tool's name anywhere in the
  repo suppresses the finding, so dead tools named like common verbs escape.
- **TypeScript tools are out of scope.** The liveness analysis is Python-only;
  a dead `tool({...})` in a TS repo carries no verdict and never fires.
- **Wiring the tool in satisfies the rule but not the review debt.** The fix's
  second branch makes the finding disappear without anyone re-auditing the
  tool's body — the rule verifies reachability intent, not tool safety; the
  rest of this policy and the shell/network policies take over once it is live.

---

## Recommendations beyond the fix

The safe pattern — a router-oriented docstring, narrow parameter types, and
distinct verb-noun names — is in
[claude_sdk/tool_definition.md](../claude_sdk/tool_definition.md#recommendations-beyond-the-fix).
For the OpenAI SDK, keep `strict_mode` at its default `True` (see OAI-003) so the
type hints you add are actually enforced at runtime.

For OAI-025, the safe pattern is a direct, statically visible wiring — every
tool the repo defines is either named in an agent's `tools=[...]` or gone:

```python
from agents import Agent, function_tool


@function_tool
def send_invoice(customer_id: str, amount_cents: int) -> str:
    """Send an invoice to a customer. Call when the user asks to bill someone."""
    ...


billing_agent = Agent(
    name="billing",
    instructions="Handle billing requests.",
    # Direct name reference: the model wiring and Trustabl's liveness
    # analysis both see it. No string-keyed registry, no getattr.
    tools=[send_invoice],
)
```

1. When a tool is intentionally parked (kept for a planned feature), move it
   out of the importable tool modules — a `graveyard/` or a feature branch —
   so it cannot be wired in by a bulk import.
2. If dynamic dispatch is unavoidable, keep a static manifest that references
   each tool by name (`_ALL_TOOLS = [send_invoice, refund_order]`) next to the
   registry, so liveness sees the identifiers and reviewers see the roster.
3. When acting on the fix's second branch (wiring a dead tool in), re-review
   the tool body first — the finding means it has been outside review pressure
   for as long as it has been unreferenced.
4. Delete, do not comment out: a commented-out wiring leaves the definition
   live to the next refactor while still reading as "someone meant this".
