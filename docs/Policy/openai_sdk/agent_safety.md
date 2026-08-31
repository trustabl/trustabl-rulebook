---
policy_id: openai_sdk_agent_safety
category: openai_sdk
topic: agent_safety
rules:
  - id: OAI-101
    severity: high
    confidence: 0.85
    scope: agent
    fix_type: config
  - id: OAI-102
    severity: high
    confidence: 0.95
    scope: agent
    fix_type: config
  - id: OAI-103
    severity: high
    confidence: 0.95
    scope: agent
    fix_type: config
  - id: OAI-104
    severity: medium
    confidence: 0.75
    scope: agent
    fix_type: config
  - id: OAI-109
    severity: high
    confidence: 0.85
    scope: agent
    fix_type: config
  - id: OAI-110
    severity: medium
    confidence: 0.6
    scope: agent
    fix_type: config
  - id: OAI-112
    severity: low
    confidence: 0.6
    scope: agent
    fix_type: config
  - id: OAI-105
    severity: high
    confidence: 0.8
    scope: agent
    fix_type: config
  - id: OAI-107
    severity: high
    confidence: 0.85
    scope: agent
    fix_type: config
  - id: OAI-114
    severity: high
    confidence: 0.6
    scope: agent
    fix_type: config
  - id: OAI-113
    severity: medium
    confidence: 0.6
    scope: agent
    fix_type: config
references: [LLM01, LLM06, LLM10]
---

# Policy Rationale: Agent Wiring Safety

**Policy ID:** `openai_sdk_agent_safety`  
**File:** `openai_sdk/agent_safety.yaml`  
**Rules:** OAI-101, OAI-102, OAI-103, OAI-104, OAI-109, OAI-110, OAI-112, OAI-105, OAI-107, OAI-114, OAI-113  
**Severities:** high, high, high, medium, high, medium, low, high, high, high, medium  
**Fix types:** config, config, config, config, config, config, config, config, config, config, config  
**References:** LLM01, LLM06, LLM10

---

## What this policy covers

How an OpenAI Agents SDK `Agent(...)` / `SandboxAgent(...)` is wired — its
guardrails, its tool-loop controls, its class choice, and the hosted tools it
mounts. These fire per agent (scope: agent) on the constructor kwargs and the
resolved tool graph: OAI-101 (no `input_guardrails` while wiring shell/filesystem
tools), OAI-102 (`tool_use_behavior="stop_on_first_tool"`), OAI-103
(`tool_choice="required"` + `reset_tool_choice=False`), OAI-104 (raw `Agent`, not
`SandboxAgent`, with shell/filesystem tools), OAI-109 (`WebSearchTool` without
`input_guardrails`), OAI-110 (a content-fetching hosted tool without
`output_guardrails`). A further rule, OAI-112, is different in kind: it does not
read the constructor at all, but correlates this agent's construction site to the
`Runner.run`/`run_sync`/`run_streamed` call(s) that execute it and fires when none
of them sets `max_turns` — an execution-limit / reliability concern (LLM10,
Unbounded Consumption), distinct from the prompt-injection and excessive-agency
framing of the rules above it. Finally, three composition rules extend the
per-agent read across the resolved `handoffs=` graph: OAI-107 (an agent that is
itself a resolved handoff target while wiring shell-reaching tools) and the
complementary pair OAI-113 / OAI-114 (an agent whose handoff chain reaches shell
capability its own wiring does not provide — OAI-113 when the agent declares no
`input_guardrails`, OAI-114 when it does).

---

## Why agent wiring is a distinct concern in agent tools

A tool's safety is necessary but not sufficient; the *agent* decides which tools to
call, in what loop, and with what screening around them. The OpenAI Agents SDK
gives authors the controls to make those decisions safe — `input_guardrails` /
`output_guardrails` to screen ingress and egress, `SandboxAgent` to confine
privileged tools, sane defaults for the tool loop — but each can be omitted or
overridden into an unsafe shape. These rules detect the unsafe wirings.

Two threat lines run through them. The **prompt-injection** line (OWASP LLM01):
an agent that wires shell/filesystem tools (OAI-101), web search (OAI-109), or a
content-fetching tool (OAI-110) is ingesting or acting on untrusted input, and the
SDK's guardrails are the primary screen — missing them leaves the model's
instruction and egress channels unprotected. The **excessive-agency / loop-control**
line (OWASP LLM06): `stop_on_first_tool` (OAI-102) makes a raw, possibly
attacker-controlled tool output the final response with no model post-processing;
`tool_choice="required"` with `reset_tool_choice=False` (OAI-103) is the SDK's
documented infinite-tool-loop footgun; a raw `Agent` instead of `SandboxAgent`
(OAI-104) surfaces the host to privileged tools directly.

A third line — **delegation** — runs through OAI-107, OAI-113 and OAI-114, and
follows from a single SDK fact: `input_guardrails` run only on the agent that
first receives the user input, and a handoff target never runs its own
`input_guardrails` on the delegated turn. Guardrails therefore protect an agent's
*own* tool surface, not its reach. An agent that delegates — directly or through
a chain — to a shell-wielding peer has shell reach with no screen in front of it
(OAI-113/114, computed as the transitive capability closure over resolved
`handoffs=` edges), and the delegate itself executes privileged tools on turns
its declared guardrails never see (OAI-107). The chain is what defeats review:
each constructor looks safe in isolation — the guarded parent holds no dangerous
tools, the child "is internal" — and the exposure exists only in the composition.

A fourth line, independent of the three, runs through OAI-112 alone and is not a threat
to injected content or agent capability at all: it is an execution-limit /
reliability concern (OWASP LLM10, Unbounded Consumption). The `Runner.run` family
is what actually drives an agent's tool loop to completion, and if none of the
calls that execute this agent sets `max_turns`, the run proceeds to whatever
ceiling the SDK's own `DEFAULT_MAX_TURNS` applies rather than to a bound sized for
the task. A model that loops or oscillates keeps consuming turns, tokens, and tool
side effects — including from any of the tools OAI-101/104/109/110 are already
screening — until that implicit ceiling intervenes, and the ceiling itself is an
SDK implementation detail that can shift between releases with no change on the
project's side. This is the same shape as CrewAI's CREW-110 (`max_iter`) and the
Claude Agent SDK's CSDK-204 (`max_turns` on `ClaudeAgentOptions`): a generic
default already bounds the worst case, so the risk is real but modest — which is
why it sits at low severity.

All of the wiring fixes above — the delegation rules included — are *config*:
guardrail lists, a kwarg, a class swap, or handoff wiring on the agent
constructor, not tool-code changes. OAI-112's fix is config
too, but at a different site: the `Runner.run(...)` call that executes the
agent, not the `Agent(...)`/`SandboxAgent(...)` constructor — the first fix in
this policy that reaches past the constructor to the call that actually runs it.

---

## Rule-by-rule defense

### OAI-101 — No input_guardrails while wiring shell/filesystem tools (Severity: high, Confidence: 0.85, Fix type: config)

**What we detect:** an agent with an empty `input_guardrails` whose resolved tools
include a shell- or filesystem-touching tool (`agent_kwarg_list_empty` +
`agent_uses_tool_kind: [shell_invocation]`).

**Why it is flaggable:** a prompt-injected input can reach a privileged tool with no
pre-execution screen — guardrails are the SDK's primary injection defense.

**Real-world consequence:** a user message crafted to trigger a file-deleting tool
reaches it unchecked.

**Why high not medium:** it leaves the main injection-defense surface empty on an
agent that holds dangerous tools.

**Fix type — config:** add an `@input_guardrail` and wire it via
`input_guardrails=[...]`.

**Confidence 0.85:** the agent may screen input by another mechanism the rule cannot
see (uncommon).

### OAI-102 — tool_use_behavior="stop_on_first_tool" (Severity: high, Confidence: 0.95, Fix type: config)

**What we detect:** `tool_use_behavior="stop_on_first_tool"` (`agent_kwarg_value`).

**Why it is flaggable:** the first tool's raw output becomes the final response with
no model post-processing — if that output is attacker-controlled (web/file/MCP
data), it is rendered to the user verbatim.

**Real-world consequence:** a search tool returns an attacker page's text and it is
shown to the user as the agent's answer — an exfiltration/injection vector.

**Why high not medium:** it removes the model's mediation of tool output entirely.

**Fix type — config:** drop the kwarg (default `run_llm_again` is safe) or constrain
via `StopAtTools(...)` listing only tools whose output you control.

**Confidence 0.95:** the literal value is read directly.

### OAI-103 — tool_choice="required" + reset_tool_choice=False (Severity: high, Confidence: 0.95, Fix type: config)

**What we detect:** `model_settings.tool_choice="required"` AND
`reset_tool_choice=False` (two `agent_kwarg_value` checks).

**Why it is flaggable:** the model is forced to call a tool every turn and the choice
is never reset — the SDK's documented infinite-loop pattern.

**Real-world consequence:** the agent loops indefinitely, exhausting the turn budget
and incurring cost, never terminating.

**Why high not medium:** it is a denial-of-progress footgun with a deterministic
trigger.

**Fix type — config:** drop `reset_tool_choice=False` (default `True` breaks the
loop) or set `tool_choice="auto"`; if forced tool use is intended, ensure a tool
terminates via `tool_use_behavior=StopAtTools(...)`.

**Confidence 0.95:** both literals are read directly.

### OAI-104 — Raw Agent (not SandboxAgent) with shell/filesystem tools (Severity: medium, Confidence: 0.75, Fix type: config)

**What we detect:** `agent_class: [Agent]` with a resolved shell/filesystem tool.

**Why it is flaggable:** the SDK ships `SandboxAgent` to confine privileged tools;
a plain `Agent` surfaces the host environment directly.

**Real-world consequence:** a file or shell tool on a raw `Agent` operates against
the real host filesystem rather than an isolated workspace.

**Why medium not high:** sandboxing is defense-in-depth; the tools may already be
individually guarded, so the missing sandbox is a weakened posture rather than an
open hole.

**Fix type — config:** switch to `SandboxAgent(...)` with a `Manifest` restricting
paths/commands.

**Confidence 0.75:** the privileged tools might be safe in context, or sandboxed by
other means — hence the lower confidence and medium severity.

### OAI-105 — TypeScript agent wires a content-fetching hosted tool without inputGuardrails (Severity: high, Confidence: 0.8, Fix type: config)

**What we detect:**
A TypeScript OpenAI Agents SDK `Agent({...})` that wires a content-fetching hosted
tool — `webSearchTool`, `fileSearchTool`, or `hostedMcpTool` (the camelCase TS
factory classes, read off `HostedToolRefs`) — AND has an empty `inputGuardrails`
(`agent_uses_hosted_tool_class: [webSearchTool, fileSearchTool, hostedMcpTool]` AND
`agent_kwarg_list_empty: [inputGuardrails]`). Because the first clause requires a
*resolved* hosted-tool reference, an agent whose options object is opaque
(non-literal) cannot trip the rule on the empty-list clause alone — it must have a
recognized hosted tool. This is the TypeScript analogue of the Python sibling
[OAI-109](#oai-109--websearchtool-without-input_guardrails-severity-high-confidence-085-fix-type-config),
widened to file search and hosted MCP and using the TS camelCase factory names and
`inputGuardrails` kwarg spelling.

**Why it is flaggable:**
These tools pull untrusted external content into the model — web pages, indexed
files, or MCP-advertised tool output — that can carry prompt-injection payloads.
With no `inputGuardrails` screening what reaches the model, injected instructions
can hijack the agent into exfiltrating data or invoking other tools. Input
guardrails are the SDK's primary ingress screen.

**Real-world consequence:**
A TS research agent wiring `webSearchTool()` with no `inputGuardrails` retrieves an
attacker-seeded page whose "ignore previous instructions…" content becomes context
and steers the next action; a `hostedMcpTool` pointed at an untrusted MCP endpoint
returns tool output that does the same.

**Why severity is high and not medium:**
Untrusted-content intake with the primary ingress screen empty is a direct
prompt-injection path, exactly as for the Python OAI-109 — high.

**Fix type — config:**
Adding a guardrail built with `defineInputGuardrail(...)` and wiring it via
`inputGuardrails: [...]` on the `Agent({...})` constructor is a wiring change, not a
tool-code edit. Pinning `hostedMcpTool` to trusted endpoints is likewise config.

**Confidence 0.8:**
A notch below the Python OAI-109's 0.85. The resolved-hosted-tool requirement
removes the dominant false positive (an agent with no content-fetching tool cannot
fire), but the gap remains that the agent may screen ingress by a mechanism the
rule cannot see — a wrapper/factory that injects guardrails, or a guardrail list
built from a non-literal value that the static read records as empty. The wider tool
set (three classes, including `hostedMcpTool` whose risk depends on the MCP
endpoint's trust) also admits more context-dependent legitimate use than OAI-109's
single `WebSearchTool`, which is why it sits at 0.8 rather than 0.85.

### OAI-107 — Handoff-target agent wires shell or filesystem-touching tools (Severity: high, Confidence: 0.85, Fix type: config)

**What we detect:**
An agent that appears as a *resolved* handoff target in another agent's
`handoffs=[...]` (predicate `agent_is_subagent_of_any` — true when this agent is
the `Resolved` entry of any agent's `HandoffRefs`, matched by name and file path;
self-handoff edges count) AND whose resolved tool graph gives it shell reach
(`agent_uses_tool_kind: [shell_invocation]` — a bare shell-invoking function, a
decorated `@function_tool` whose body discovery stamped with the structural
`shells_out` fact, or a hosted shell-grade tool class such as `ShellTool`,
`LocalShellTool`, `CodeInterpreterTool`, or `ApplyPatchTool`). Both clauses read
the discovery graph, not raw source: the handoff edge must have resolved
(same-file, by `Name` or `VarName`), and the shell reach must come from a
resolved or hosted tool reference.

**Why it is flaggable:**
In the OpenAI Agents SDK, `input_guardrails` run only on the agent that first
receives the user input — a handoff target never runs its own `input_guardrails`
on the delegated turn. A parent can therefore route around its own screen by
delegating: the child's shell-touching tools execute on a payload no guardrail
ever inspected. This is why the rule deliberately does *not* require the child's
`input_guardrails` to be empty — a child that declares guardrails still does not
run them on the handed-off turn, so the shell exposure is the hazard regardless
of the child's own configuration.

**Real-world consequence:**
A triage agent with solid `input_guardrails` hands "run the diagnostics the user
asked for" to a fix-it child holding a `subprocess`-wrapping tool. A
prompt-injected user message the parent's guardrail was never written to catch —
it screens the parent's own tool surface, not the child's — arrives at the child
reformulated as an innocuous-looking delegation payload and drives
`rm`/`curl`-grade commands with nothing in front of them.

**Why severity is high and not medium — or critical:**
High for the same reason as OAI-101: an unscreened path from model-influenced
input to shell execution, on the SDK's primary defense surface. It is not medium
because the bypass is not conditional on a misconfiguration elsewhere — the SDK's
guardrail placement *guarantees* the child's screen never runs on delegated
turns, so the gap exists whenever the edge is exercised. It stays off critical
because execution still requires the parent to actually delegate
attacker-influenced content, and a handoff `input_filter` or tool-level
validation may constrain the payload in ways the static read cannot see.

**Fix type — config:**
Every remediation is wiring: remove the shell tools from the handoff target, move
the privileged work up to the guarded entry agent, or constrain the delegated
payload with an `input_filter` on the handoff plus a parent-side
`@input_guardrail`. No tool source changes.

**Confidence 0.85:**
The same number as OAI-101, for the same shape of gap: the mechanism is
unconditional, but mitigations outside the two predicates' sight exist. The
parent may attach an `input_filter` to the handoff (discovery does not model
input filters), the child's shell tool may validate or allow-list internally, or
the child may in practice only ever be run as a top-level agent — where its
guardrails *do* run — with the handoff edge vestigial. In the other direction the
rule under-fires rather than over-fires: a `handoffs=` list item wrapped in the
`handoff(...)` helper resolves External rather than to the target (a documented
v1 limitation), a cross-file target resolves External, and a post-construction
`agent.handoffs = [...]` assignment is never captured — all false negatives that
cost coverage, not confidence.

### OAI-109 — WebSearchTool without input_guardrails (Severity: high, Confidence: 0.85, Fix type: config)

**What we detect:** `agent_uses_hosted_tool_class: [WebSearchTool]` with empty
`input_guardrails`.

**Why it is flaggable:** web search returns untrusted external content that can carry
prompt-injection payloads, with no pre-screen.

**Real-world consequence:** the agent searches an attacker-controlled page; its
injected instructions hijack subsequent behavior.

**Why high not medium:** untrusted-content intake with no guardrail is a primary
injection path.

**Fix type — config:** add an `@input_guardrail` that validates queries before they
reach `WebSearchTool`.

**Confidence 0.85:** the agent might screen by another route the rule cannot see.

### OAI-110 — Content-fetching tool without output_guardrails (Severity: medium, Confidence: 0.6, Fix type: config)

**What we detect:** empty `output_guardrails` while the agent wires `WebSearchTool`,
`FileSearchTool`, or `CodeInterpreterTool`.

**Why it is flaggable:** these pull untrusted content in; output guardrails are the
SDK's egress screen on the final response. Without them a prompt-injected tool result
can drive an exfiltrating or unsafe answer with nothing inspecting what leaves.

**Real-world consequence:** injected content in a fetched document steers the final
response to leak data, unscreened.

**Why severity is medium:** output guardrails are far from universally adopted, and
many content-fetching agents handle only low-risk public data, so a missing egress
screen is often acceptable (see the 0.6 confidence). It stays above low because, on
an agent that ingests untrusted content and can act on it, the absent screen is the
last line before the user/caller.

**Fix type — config:** add an `@output_guardrail` and wire `output_guardrails=[...]`.

**Confidence 0.6:** the lower confidence reflects that many content-fetching agents
are low-risk (public data, no sensitive egress), so the missing output guardrail is
often acceptable — a review prompt more than a defect.

### OAI-112 — OpenAI Agents SDK agent has no explicit max_turns limit (Severity: low, Confidence: 0.6, Fix type: config)

**What we detect:** this agent has at least one resolvable `Runner.run` /
`run_sync` / `run_streamed` call that executes it — found by a second,
independent discovery pass that matches the call's callee object to exactly
`Runner` (or a dotted path ending in `.Runner`) and its first positional
argument to this agent's `VarName`, in the same file — and none of those calls
sets `max_turns` (predicate `agent_run_call_max_turns_missing`). Unlike every
other rule in this policy, which reads kwargs off a single constructor call,
OAI-112 correlates two separately discovered structures — the agent's
`AgentDef` and one or more `AgentRunCallDef`s — by same-file variable name. A
call whose first argument is not a plain identifier (a call expression, a
keyword arg) is skipped as unresolvable, and an agent with no matching run
call at all never fires: no resolvable execution site is not evidence that one
is missing a cap.

**Why it is flaggable:** with no `max_turns` on any call that runs it, the
agent's loop runs to whatever ceiling the SDK's `DEFAULT_MAX_TURNS` applies
rather than to a bound sized for this task. A model that loops or oscillates —
retrying a failing tool, re-reading the same file, ping-ponging between two
steps — keeps consuming turns, tokens, and tool side effects until that
implicit ceiling is reached, and an implicit ceiling can shift between SDK
versions without any change on your side.

**Real-world consequence:** an agent wired with a flaky tool is run via
`Runner.run(agent, user_input)` with no `max_turns`; a transient failure sends
it into a retry-and-fail loop that burns turns, tokens, and tool side effects
until the SDK's own default finally intervenes — a slow, silent cost overrun
rather than a clean stop at a bound the team chose.

**Why severity is low and not medium:** the SDK's own `DEFAULT_MAX_TURNS`
bounds the worst case, so this is not an unbounded-loop finding — it is a
missing *explicit, task-sized* bound. That places it alongside CrewAI's
CREW-110 (`max_iter`) and the Claude Agent SDK's CSDK-204 (`max_turns` on
`ClaudeAgentOptions`): a generic ceiling already limits the damage, so the
finding is real but modest.

**Fix type — config:** pass `max_turns=` to `Runner.run(...)` (or
`run_sync`/`run_streamed`), sized to the work this agent actually does. Unlike
every other fix in this policy, this one is not a constructor kwarg — it lands
on the call that executes the agent, a different site entirely. Treat hitting
the cap as a signal to surface and handle rather than to raise it: if a task
legitimately needs many turns, split it into bounded sub-runs instead of
removing the bound.

**Confidence 0.6:** lower than every kwarg-presence/absence rule above because
the predicate does something none of them do — it correlates two separately
discovered structures, `AgentDef` and `AgentRunCallDef`, by same-file variable
name, rather than reading kwargs off one call. That correlation has two real
gaps. Cross-file correlation is not attempted at all: an agent constructed in
one file and run via `Runner.run(...)` in another is invisible to this rule
and never fires — a false negative the rule does not attempt to close. And
because the check only asks whether *any* matching run call sets `max_turns`,
an agent run multiple times with inconsistent settings — one call sizing
`max_turns`, another leaving it off — goes completely silent on the strength
of the one compliant call, even though the uncapped call still executes the
same agent unbounded. The remaining gaps mirror CSDK-204's own 0.6: a call
built with `**` unpacking is skipped as unresolvable (`Opaque: true`), a cap
enforced by a wrapper or retry harness outside the call itself is invisible,
and a `max_turns` value passed via a variable the scanner cannot resolve to a
literal reads as absent.

### OAI-113 — Unguarded agent's handoff chain reaches shell execution (Severity: medium, Confidence: 0.6, Fix type: config)

**What we detect:**
An agent whose constructor has no `input_guardrails` kwarg at all
(`not: agent_kwarg_present: [input_guardrails]` — pure key-presence, so even
`input_guardrails=None` or `=[]` moves the agent out of this rule and into
OAI-114) AND whose transitive capability closure contains `shell` while its own
wiring provides none (`transitive_capability_exceeds_direct: [shell]`). The
closure is `analysis.ComputeComposition`'s fixpoint over resolved handoff edges —
the agent's own tool capabilities plus everything reachable through `handoffs=`
chains, in the closed alphabet shell/code_exec/filesystem/network — and the
"direct" side is recomputed with the same derivation
(`analysis.DirectCapabilities`), so the two sides cannot drift. An agent with an
empty closure matches nothing: composition rules only fire on agents the
analysis actually classified.

**Why it is flaggable:**
If this agent is where user input enters, nothing screens that input anywhere on
a delegation path that ends in shell execution: `input_guardrails` run only on
the first agent in the run, and handoff targets never run their own on delegated
turns. The `exceeds_direct` shape is what makes the finding non-obvious — this
agent holds no dangerous tool itself, so nothing in its own constructor suggests
shell exposure, yet a resolved chain gives the model a path from this agent's
input to a shell.

**Real-world consequence:**
A front-door router with no guardrails delegates to a planner, which delegates to
an executor holding a `subprocess`-wrapping tool. An injected request traverses
both hops and shells out — and no single-constructor review would have caught
it: the router has no dangerous tools, the planner has none either, and the
executor "is internal."

**Why severity is medium and not high:**
Two reasons. First, the dangerous node already carries the high-severity alarm:
whenever this rule fires over resolved edges, the shell-holding agent in the
chain is itself a resolved handoff target with shell-reaching tools, so OAI-107
fires there at high — this finding adds entry-point attribution, not the primary
alert. Second, the rule cannot prove this agent is actually the run entry point;
for an agent that only ever receives delegated turns, its own `input_guardrails`
would not run anyway, so their absence changes nothing there. Conditional impact
plus overlap with a high-severity sibling is the same calibration that puts
OAI-104 at medium.

**Fix type — config:**
Add `input_guardrails=[...]` on this constructor so the entry point of the chain
screens input before any downstream shell tool can act on it — one kwarg, no
tool source changes. Reviewing whether the downstream agent needs shell at all
is likewise wiring.

**Confidence 0.6:**
The composition predicates carry gaps the single-constructor rules above do not.
The closure is computed over constructor-kwarg handoff edges only: a chain wired
by post-construction attribute assignment (`agent.handoffs = [b]`) is invisible,
as is a `handoffs=` item wrapped in the `handoff(...)` helper or a target defined
in another file (both resolve External) — false negatives that also make the
closure a lower bound. On the false positive side: the rule cannot tell whether
this agent is actually where user input enters (a mid-chain agent's guardrails
would not run regardless); an `input_filter` on any hop may already constrain the
delegated payload exactly as the fix recommends, invisibly; and the `shell`
classification is structural (tool kind, `shells_out` fact, hosted class), so a
downstream tool whose subprocess call is internally allow-listed still counts.
Those over- and under-reads together hold it at 0.6.

### OAI-114 — Guarded agent transitively wields shell through its handoff chain (Severity: high, Confidence: 0.6, Fix type: config)

**What we detect:**
The complement of OAI-113 on the same closure: the constructor HAS an
`input_guardrails` kwarg (`agent_kwarg_present: [input_guardrails]` — pure
presence, no value inspection) AND `transitive_capability_exceeds_direct:
[shell]` — the closure over resolved handoff edges includes `shell` while the
agent's own wiring provides none. The pair partitions every
transitive-shell-excess agent: exactly one of OAI-113/OAI-114 fires, keyed on
whether the kwarg appears.

A note on the id, for readers of older material: this rule was numbered
**OAI-112** before the fixture/production reconciliation. Production's shipped
`max_turns` rule already held OAI-112, and shipped ids never change, so the
renumber landed on this — then unshipped — side: the transitive-shell
composition rule became OAI-114, and OAI-112 now permanently names the
`max_turns` rule documented above. Older drafts citing OAI-112 for transitive
shell reach mean this rule.

**Why it is flaggable:**
The declared guardrails create false confidence. `input_guardrails` run only
where user input first lands; every delegated turn downstream runs unscreened,
and the handoff may transform the payload before it reaches the shell-wielding
agent — so the screen the author wrote covers precisely the turns that never
touch a shell. A reviewer reading this constructor sees guardrails present and
no dangerous tools wired, and reasonably concludes the agent is safe; the danger
is one resolved edge away, in a direction the guardrail mechanism structurally
cannot cover.

**Real-world consequence:**
A support agent with strict `input_guardrails` — written and tested against its
*own* tool surface — delegates "escalate to ops" to an ops agent whose tools
shell out. An injection phrased as an escalation request passes the parent's
guardrail (which screens for misuse of the parent's tools), is reformulated by
the model into the handoff payload, and executes downstream where no guardrail
runs. The team's security review signed off on the parent because the guardrails
were demonstrably present.

**Why severity is high and not medium:**
Deliberately one tier above its unguarded sibling OAI-113, and the inversion is
the point: a control that is present but silently inapplicable is worse than an
honest absence. OAI-113's missing kwarg is visible to any reviewer; here the
declared guardrails actively defeat review — the agent *looks* covered, so
nobody adds the compensating `input_filter` or moves the privileged work up. The
remediation also belongs unambiguously to this agent: it declared both the
guardrails and the handoff, whereas OAI-113's primary alarm is carried by
OAI-107 on the downstream target. It stays off critical for the same reasons as
OAI-107: attacker-influenced content must actually be delegated, and
out-of-sight mitigations (an `input_filter`, tool-level validation) may exist.

**Fix type — config:**
All three remediations are wiring, not tool code: move the shell-wielding work
up to this agent where its guardrails actually run, remove the shell tools from
the downstream agent, or constrain the delegated payload with an `input_filter`
on the handoff (pairing it with tool-level validation downstream is
defense-in-depth beyond the rule's ask).

**Confidence 0.6:**
Every composition gap listed under OAI-113 applies verbatim: the closure is
computed over constructor-kwarg handoff edges only, so a post-construction
`agent.handoffs = [...]` assignment is invisible; `handoff(...)`-wrapped and
cross-file targets resolve External (false negatives); an `input_filter` on any
hop is invisible (false positive); and `shell` classification is structural. Two
more gaps are specific to this rule's "guarded" premise. `agent_kwarg_present`
is pure key-presence: `input_guardrails=None` or `input_guardrails=[]` counts as
guarded, so an effectively unguarded agent can land here with the
false-confidence framing overstated — the exposure is real either way, but it
belonged in OAI-113's framing. And presence says nothing about quality: a no-op
guardrail satisfies the clause exactly as it satisfies OAI-101. The 0.6 matches
OAI-113 because the dominant uncertainty — the closure's blind spots and the
filter blindness — is shared.

---

## What this policy does not cover

- The *quality* of guardrails that are present — a no-op `input_guardrail` /
  `output_guardrail` satisfies OAI-101/106/109/110 without screening anything.
- Filesystem-only capability: `agent_uses_tool_kind: [shell_invocation]`
  (OAI-101/104/107) matches bare shell-invoking functions, decorated tools
  discovery stamped with the `shells_out` fact, and hosted shell-grade classes
  (`ShellTool`, `LocalShellTool`, `CodeInterpreterTool`, `ApplyPatchTool`) — but
  a tool that only reads or writes the filesystem without shelling out matches
  nothing, so the "or filesystem-touching" half of those rules' titles is
  delivered only when the file access rides on a shell.
- Handoff coverage (OAI-107/113/114) is Python-only and edge-limited: the rules
  read resolved constructor-kwarg `handoffs=` edges. A TypeScript OpenAI agent's
  handoff chain has no equivalent rules; a `handoffs=` item wrapped in the
  `handoff(...)` helper, a target defined in another file, or a
  post-construction `agent.handoffs = [...]` assignment resolves External or is
  never captured, so those chains fire nothing.
- An `input_filter` on a handoff — the very mitigation OAI-107/114's fix text
  recommends — is invisible to discovery, so a chain already constrained per the
  fix still fires (known false positive).
- OAI-113/114 fire only when transitive shell *exceeds* direct: an agent that
  both wields shell itself and delegates to shell is covered by the direct rules
  alone — the chain adds no separate finding on that agent.
- Guardrails or sandboxing applied by a wrapper/factory the static check cannot see.
- For OAI-105: a TypeScript agent whose options object (and therefore its hosted-tool
  list) is opaque to the static read fires nothing — the rule requires a *resolved*
  `webSearchTool`/`fileSearchTool`/`hostedMcpTool` reference, so a content-fetching
  tool wired through a non-literal value is a false negative; and an
  `inputGuardrails` list built from a non-literal value reads as empty even when a
  guardrail is present (false positive).
- For OAI-112: an agent constructed in one file and executed via
  `Runner.run(...)` in another — the `AgentDef`-to-`AgentRunCallDef`
  correlation is same-file-VarName only, so a cross-file execution site is
  invisible and the rule stays silent. An agent run multiple times where only
  one call sets `max_turns` also escapes detection: any single matching call
  that sets it silences the finding entirely, even if other calls that execute
  the same agent leave it uncapped. The SDK's actual `DEFAULT_MAX_TURNS`
  behavior is not independently verified for this doc beyond the language
  already present in the shipped rule's own explanation text.

---

## Recommendations beyond the fix

```python
from agents import Agent, SandboxAgent, Runner, handoff, input_guardrail, output_guardrail

agent = SandboxAgent(
    name="research",
    tools=[web_search, read_file],
    input_guardrails=[screen_user_input],     # OAI-101/109
    output_guardrails=[screen_final_output],  # OAI-110
    # no stop_on_first_tool; tool_choice left "auto"  -> OAI-102/103
)

result = Runner.run_sync(agent, user_input, max_turns=8)  # OAI-112: sized to this agent's task

# Delegation (OAI-107/113/114): privileged work stays on the guarded entry
# agent; a handoff that must exist gets an explicit payload filter, because
# the child's own input_guardrails will NOT run on the delegated turn.
ops = Agent(name="ops", tools=[restart_service])  # no shell reach on the target
triage = Agent(
    name="triage",
    input_guardrails=[screen_user_input],
    handoffs=[handoff(ops, input_filter=keep_only_ticket_id)],
)
```

1. Wire both `input_guardrails` and `output_guardrails` on any agent that touches
   untrusted content or privileged tools; make them real screens, not stubs.
2. Leave the tool-loop defaults alone — avoid `stop_on_first_tool` and the
   `tool_choice="required"` + `reset_tool_choice=False` pairing unless a tool
   deterministically terminates the loop.
3. Prefer `SandboxAgent` with a restrictive `Manifest` for any agent holding
   shell/filesystem tools — including handoff targets, where sandboxing is one
   of the few screens that still applies on delegated turns.
4. Treat every handoff as a trust boundary: keep shell tools off handoff targets
   where possible, attach an `input_filter` that reduces the delegated payload
   to the minimum the child needs, and validate inside the downstream tools
   themselves — a child's own `input_guardrails` never run on delegated turns,
   so parent-side screening and tool-level checks are the only ones that do.
5. Pass `max_turns=` on whichever `Runner.run`/`run_sync`/`run_streamed` call
   executes the agent, sized to the task rather than left at the SDK default,
   and keep it consistent across every call site that runs the same agent.
