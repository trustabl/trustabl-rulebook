---
policy_id: openai_sdk_mcp_safety
category: openai_sdk
topic: mcp_safety
rules:
  - id: OAI-106
    severity: high
    confidence: 0.9
    scope: agent
    fix_type: config
  - id: OAI-115
    severity: high
    confidence: 0.7
    scope: agent
    fix_type: config
  - id: OAI-116
    severity: high
    confidence: 0.75
    scope: agent
    fix_type: config
  - id: OAI-117
    severity: medium
    confidence: 0.65
    scope: agent
    fix_type: config
references: [LLM01, LLM06]
---

# Policy Rationale: MCP Integration Safety

**Policy ID:** `openai_sdk_mcp_safety`  
**File:** `openai_sdk/mcp_safety.yaml`  
**Rules:** OAI-106, OAI-115, OAI-116, OAI-117  
**Severities:** high, high, high, medium  
**Fix types:** config, config, config, config
**References:** LLM01, LLM06

---

## What this policy covers

Two related but distinct gaps in how an OpenAI Agents SDK agent wires MCP:

- **OAI-106** — agents that import tools from one or more MCP servers via
  `mcp_servers=` (present and non-empty — an empty `mcp_servers=[]` wires
  nothing and does not fire) but configure no `input_guardrails`. The match is
  `agent_kwarg_present: [mcp_servers]` AND NOT `agent_kwarg_list_empty:
  [mcp_servers]` AND `agent_kwarg_list_empty: [input_guardrails]` — it fires
  only when MCP is actually wired, so non-MCP agents are unaffected.
- **OAI-115** — agents that wire a `HostedMCPTool(tool_config={...})` (the
  SDK's hosted, Responses-API-mediated MCP integration, a separate mechanism
  from `mcp_servers=`) whose `tool_config` sets no `allowed_tools`. The match
  is `agent_uses_hosted_tool_class: [HostedMCPTool]` AND NOT
  `agent_hosted_tool_kwarg_present: {class: HostedMCPTool, kwarg:
  tool_config.allowed_tools}` — the same `not: <hosted-kwarg-present>` shape
  Google ADK's `ADK-111` uses for `MCPToolset`/`tool_filter`.
- **OAI-116** — the TypeScript sibling of OAI-115: agents that wire a
  `hostedMcpTool({...})` factory call (`@openai/agents`) whose options set no
  `allowedTools`. Same match shape, TS-flavored: `agent_uses_hosted_tool_class:
  [hostedMcpTool]` AND NOT `agent_hosted_tool_kwarg_present: {class:
  hostedMcpTool, kwarg: allowedTools}`. The TS SDK's options object is flat —
  `allowedTools` sits directly on the factory call, with no `tool_config` /
  `toolConfig` wrapper — so the kwarg path has one segment where Python's has
  two.
- **OAI-117** — a distinct, independent gap on the same TS `hostedMcpTool`
  construct: options that omit `requireApproval` entirely. The match is
  `agent_uses_hosted_tool_class: [hostedMcpTool]` AND NOT
  `agent_hosted_tool_kwarg_present: {class: hostedMcpTool, kwarg:
  requireApproval}` — same shape as OAI-116, different kwarg, and
  deliberately not combined with OAI-116's `allowedTools` check: an agent can
  set one control correctly and still be missing the other, so the two fire
  independently and can both land on the same `hostedMcpTool(...)` call.

OAI-115 and OAI-116 cover the hosted path, where the MCP server is not run by
the agent process at all. The Python `HostedMCPTool(tool_config={...})` and the
TypeScript `hostedMcpTool({...})` hand the named server to the Responses API,
which connects the model to every tool that server advertises. OAI-115 fires
when the Python `tool_config` dict sets no `allowed_tools` (match
`agent_uses_hosted_tool_class: [HostedMCPTool]` AND NOT
`agent_hosted_tool_kwarg_present` for `tool_config.allowed_tools`); OAI-116
fires when the TypeScript options set no `allowedTools`. The allow-list is the
only static narrowing of that catalog, so its absence is the finding.

---

## Why MCP integration is a distinct concern in agent tools

The Model Context Protocol lets an agent import a tool catalog advertised by an
external MCP server. The crucial property is the trust boundary: the tool *names
and descriptions* the model sees are supplied by the MCP server, not the agent
author. Those descriptions are part of the model's prompt — they tell it when and
how to call each tool — so a malicious or compromised MCP server can craft
descriptions that bait the model into harmful actions, exfiltrate data through tool
arguments, or shadow a legitimate tool with a poisoned one. This is the documented
"tool poisoning" / "rug pull" class of MCP attack, and it is a direct instance of
OWASP LLM01 (Prompt Injection): untrusted text from across a trust boundary enters
the model's instruction context.

The agent author cannot review descriptions that are fetched at runtime from a
third party, so the defense has to be an active screen: an `input_guardrail` that
inspects the user input *and* the resolved tool list before the model is invoked.
Without one there is no pre-execution checkpoint between a poisoned MCP catalog and
the model acting on it. The fix is *config* — adding a guardrail to the agent
constructor, not changing any tool's code.

`HostedMCPTool` is a second, structurally different way the same SDK reaches
MCP: instead of the agent process connecting to the server directly
(`mcp_servers=`, screened by OAI-106), `tool_config` hands a remote MCP
server's URL to OpenAI's Responses API, which lists and calls that server's
tools on the agent's behalf. There is no `input_guardrails` gate here at
all — guardrails run over the agent's own turn, not inside the hosted
tool-call loop the Responses API executes remotely. The only static control
the SDK exposes is `tool_config["allowed_tools"]`, an allow-list of tool
names; without it the agent inherits the server's entire catalog, sized and
composed however the server operator (or an attacker who compromises that
server) chooses, on a boundary this codebase does not control. This is the
same **excessive-agency / loss-of-mediation** shape (OWASP LLM06) that
Google ADK's `ADK-111` documents for `MCPToolset`/`tool_filter` — a remote
party, not the agent author, deciding the agent's tool surface — layered with
the LLM01 tool-poisoning exposure OAI-106 already covers for the
directly-connected case: every tool in an unfiltered catalog is a tool
description the model reads unfiltered too. `@openai/agents`'s TypeScript
`hostedMcpTool({...})` factory is the same mechanism under a different name
and a flat options shape — OAI-116 is its dedicated rule, per this repo's
SDK-scoped-rules discipline (a Python `HostedMCPTool` rule and a TS
`hostedMcpTool` rule stay two rules, never one `applies_to` widened across
both).

---

## Rule-by-rule defense

### OAI-106 — Agent wires MCP servers without input_guardrails (Severity: high, Confidence: 0.9, Fix type: config)

**What we detect:** an agent with `mcp_servers=` set and an empty/absent
`input_guardrails`.

**Why it is flaggable:** the agent ingests tool descriptions from an external trust
boundary with no screen between them and the model.

**Real-world consequence:** a compromised MCP server advertises a `read_file` tool
whose description instructs the model to also send file contents to an attacker
endpoint; with no guardrail the model follows it.

**Why severity is high and not medium:** the attack reaches the model's instruction
channel directly and requires only that the MCP server (a separate party) be
malicious or compromised. Not critical because it still depends on the MCP server
being hostile and on a follow-on capability.

**Fix type — config:** add an `input_guardrail` to the agent and pin MCP servers to
known-trusted URLs/checksums.

**Confidence 0.9:** the configuration is read directly — MCP wired, guardrails empty.
The small gap is an agent that screens MCP content through some other mechanism the
rule cannot see.

### OAI-115 — Agent wires a HostedMCPTool with no allowed_tools allow-list (Severity: high, Confidence: 0.7, Fix type: config)

**What we detect:** an agent whose `HostedToolRefs` include a resolved
`HostedMCPTool` (`agent_uses_hosted_tool_class: [HostedMCPTool]`) where
`tool_config.allowed_tools` is not present on that constructor's captured
kwargs (`not: agent_hosted_tool_kwarg_present {class: HostedMCPTool, kwarg:
tool_config.allowed_tools}`). `tool_config` is a Python dict literal;
discovery recurses into dict literals the same way it recurses into a nested
constructor call, so the dotted path reaches `allowed_tools` inside it. A
`HostedMCPTool()` with no `tool_config` kwarg at all — and so no
`allowed_tools` — also fires, correctly: no kwargs is the same absence of a
boundary as a `tool_config` that omits the key.

**Why it is flaggable:** every other tool in an agent's `tools=` list is
enumerable by reading the source — a function, a hosted-tool class with fixed
behavior. `HostedMCPTool` is not: it hands a URL to the Responses API and
inherits whatever tools that server currently advertises, a set decided by
the server operator, invisible from this codebase, and free to grow or change
meaning on the next server deploy with no diff in the agent's repo.
`allowed_tools` is the SDK's only static mechanism for pinning that inherited
set to a named allow-list; without it there is no boundary a reviewer, a
diff, or this scanner can check.

**Real-world consequence:** an agent wired to a hosted MCP server "for
documentation lookups" inherits a `run_query` or `write_file` tool the moment
the server ships one — no code change on the agent side, nothing for review
to catch. The `require_approval` default (`"always"`) means a human is asked
before each *individual* call, but that per-call prompt approves whatever the
server currently calls the tool, not a reviewed allow-list — and the corpus
example this rule was built against (`testdata/corpus/openai-hosted-mcp/simple.py`)
sets `require_approval: "never"`, removing even that runtime backstop while
still setting no `allowed_tools`.

**Why severity is high and not critical (or medium):** parity with ADK-111's
reasoning for the structurally identical `MCPToolset`/`tool_filter` gap: not
critical, because the finding proves inherited breadth, not inherited
danger — whether the catalog contains anything destructive depends on the
server. Not medium, because the boundary is delegated to a remote party and
can move without any change in the scanned code, converting every server
update into an ungated capability grant.

**Fix type — config:** add `allowed_tools` to the `tool_config` dict on the
`HostedMCPTool(...)` call — wiring, not tool-body code.

**Confidence 0.7 — one notch below ADK-111's 0.75:** the mechanism and
consequence are the same as ADK-111, but OpenAI's `tool_config` shape carries
one benign-fire path ADK's `MCPToolset` does not: `require_approval` defaults
to `"always"`, so an agent that never sets it retains a runtime human-in-the-
loop check per call even with no static `allowed_tools` — a real, if weaker,
mitigation this rule cannot see. The false-positive/false-negative gaps
otherwise mirror ADK-111's: a `tool_config` built from a variable or
`**kwargs` spread rather than a literal dict is not captured, so the rule
fires on a case that may in fact set `allowed_tools` dynamically; and
`allowed_tools: []` or `allowed_tools: None` both read as *present* (the
underlying presence check is `node.Value != nil`, the same tri-state gap
CSDK-204/CSDK-205 carry for their own missing-kwarg checks), silencing the
rule on an empty or explicitly-disabled allow-list that is functionally
identical to having none.

### OAI-116 — TypeScript agent wires a hostedMcpTool with no allowedTools allow-list (Severity: high, Confidence: 0.75, Fix type: config)

**What we detect:** an agent whose `HostedToolRefs` include a resolved
`hostedMcpTool` factory call (`agent_uses_hosted_tool_class: [hostedMcpTool]`)
where `allowedTools` is not present on that call's captured options
(`not: agent_hosted_tool_kwarg_present {class: hostedMcpTool, kwarg:
allowedTools}`). The TS options object is flat, so the kwarg path is a single
segment — `allowedTools`, not `tool_config.allowed_tools` — captured by
`TSObjectKwargs` regardless of whether it is written as a bare string array
(`allowedTools: ["ask_question"]`) or a filter object
(`allowedTools: { toolNames: [...] }`); both shapes give the lookup a non-nil
node and silence the rule. A `hostedMcpTool()` call with no options object at
all — and so no `allowedTools` — also fires, correctly, mirroring OAI-115's
same no-kwargs-at-all case.

**Why it is flaggable:** identical to OAI-115 — `hostedMcpTool` hands a
server URL to OpenAI's Responses API and the agent inherits whatever tools
that server currently advertises, a set decided by the server operator,
invisible from this codebase, and free to grow or change meaning on the next
server deploy with no diff in the agent's repo. `allowedTools` is the SDK's
only static mechanism for pinning that inherited set to a named allow-list.

**Real-world consequence:** the same unreviewed-catalog-growth scenario
OAI-115 documents, sharpened by a TypeScript-specific default: unlike
Python's `HostedMCPTool`, which passes `tool_config` through raw and falls
back to the Responses API's platform default of approval-required, the JS SDK
injects `require_approval: 'never'` into the wire payload whenever
`requireApproval` is omitted from the options object (verified directly in
`hostedMcpTool`'s implementation in `packages/agents-core/src/tool.ts`, not
just its docs). An agent that sets neither `allowedTools` nor
`requireApproval` therefore has no static boundary *and* no runtime human
checkpoint — every tool the server currently exposes executes without
confirmation, not merely without review.

**Why severity is high and not critical (or medium):** same reasoning as
OAI-115 and ADK-111 — the finding proves inherited breadth, not inherited
danger, so not critical; and the boundary is delegated to a remote party that
can move without any change in the scanned code, so not medium.

**Fix type — config:** add `allowedTools` to the `hostedMcpTool({...})` call's
options — wiring, not tool-body code.

**Confidence 0.75 — one notch above OAI-115's 0.7:** OAI-115's discount from
ADK-111's 0.75 is priced entirely on a benign-fire path this rule does not
have. That path is Python's platform-default approval-required fallback when
`require_approval` is omitted — a *documented API behavior*, not something
pinned by quotable SDK source, per the parent decision doc
(`docs/decisions/tool-allowlist-scope.md`). The TypeScript SDK forecloses that
same path in verifiable source: omitting `requireApproval` does not fall
through to a safer platform default, it is actively overwritten to `'never'`
inside `hostedMcpTool` itself. With the one mitigating path OAI-115 accounts
for gone, and no other gap distinguishing the two rules, OAI-116 returns to
ADK-111's 0.75 rather than inheriting OAI-115's discount. The
false-positive/false-negative gaps otherwise mirror OAI-115's: a
`hostedMcpTool({...})` call built from a spread or a variable rather than an
object literal is not captured (`TSObjectKwargs` only descends into a literal
`object` node), so the rule may fire on a case that in fact sets
`allowedTools` dynamically; `allowedTools: []` reads as *present* (the same
`node.Value != nil` / `Children != nil` tri-state gap OAI-115 and
CSDK-204/CSDK-205 all carry), silencing the rule on an explicitly-empty
allow-list that is functionally identical to having none; and a
`const mcp = hostedMcpTool({...})` referenced by identifier in `tools: [mcp]`
resolves onto `AgentDef.ToolRefs`, not `HostedToolRefs` — the hosted-tool
classification only recognizes a `hostedMcpTool(...)` call written directly
inline in the `tools:` array — so a hoisted binding escapes this rule
entirely.

### OAI-117 — TypeScript agent wires a hostedMcpTool with no requireApproval setting (Severity: medium, Confidence: 0.65, Fix type: config)

**What we detect:** an agent whose `HostedToolRefs` include a resolved
`hostedMcpTool` factory call (`agent_uses_hosted_tool_class: [hostedMcpTool]`)
where `requireApproval` is not present on that call's captured options
(`not: agent_hosted_tool_kwarg_present {class: hostedMcpTool, kwarg:
requireApproval}`). This is the single-segment flat-options lookup, same
mechanism as OAI-116's `allowedTools` check, on a different key. A
`hostedMcpTool()` call with no options object at all also fires, for the same
reason OAI-115/OAI-116 fire on a bare call: no kwargs is the same absence of
a setting as an options object that omits the key. The rule is intentionally
independent of OAI-116 — it does not check `allowedTools` at all, so an
agent that sets `allowedTools` correctly but omits `requireApproval` fires
this rule and stays silent on OAI-116, and an agent that omits both fires
both rules on the same call site.

**Why it is flaggable:** verified directly in `hostedMcpTool`'s
implementation (`packages/agents-core/src/tool.ts`, both the `serverUrl` and
`connectorId` branches): the factory checks `typeof options.requireApproval
=== 'undefined' || options.requireApproval === 'never'` and, when true,
writes `require_approval: 'never'` into the wire payload sent to the
Responses API. Omitting the option is not "leave it unset" — it is
indistinguishable, at the API boundary, from writing `requireApproval:
'never'` by hand. That silently inverts the Responses API's own platform
default (approval-required), so code that never mentions approval at all
ends up less gated than the API's baseline behavior, with nothing in the
source signaling that a human-in-the-loop check has been turned off.

**Real-world consequence:** an agent wired to a hosted MCP server for
"documentation lookups," with a correctly-scoped `allowedTools` list and no
`requireApproval` set, auto-executes every one of those allowed tools with no
confirmation step — including a rename or version bump on the server side
that reinterprets an allowed tool name to do something more consequential
than the reviewer who wrote the allow-list intended. The allow-list bounds
*which* tool names are reachable; it does not bound *whether* a call to one
of them executes unattended.

**Why severity is medium and not high (unlike OAI-115/OAI-116):** the
consequence differs in kind from the allow-list gap, not just in degree.
Absent `allowedTools` produces an unbounded, non-enumerable tool surface — a
reviewer cannot even list what the agent can call. Absent `requireApproval`
produces a bounded surface (when `allowedTools` is also set) that simply
executes without a human checkpoint — still auditable from source, just
missing a runtime gate. Stacking two `high` findings on every under-specified
`hostedMcpTool(...)` call would also overstate a single construct's risk;
medium keeps the two rules' combined signal proportionate to each control's
actual contribution.

**Fix type — config:** set `requireApproval` explicitly on the
`hostedMcpTool({...})` call's options — wiring, not tool-body code.

**Confidence 0.65 — below both OAI-115 and OAI-116:** the mechanism is
certain (verified in SDK source, not inferred), but the predicate cannot see
a real and common benign-fire path: a hosted MCP server that is genuinely
read-only (a documentation or search lookup, the same `deepwiki` shape used
throughout this policy's own examples) has no side effect for approval to
gate, and `requireApproval: 'never'` is the *correct*, deliberately-chosen
setting for it — indistinguishable from the negligent-omission case using
only the AST. The discount is sized for that specific ambiguity, not for
any weakness in the mechanical claim. The false-positive/false-negative
gaps otherwise mirror OAI-116's: a `hostedMcpTool({...})` call built from a
spread or a variable rather than an object literal is not captured; and a
`const mcp = hostedMcpTool({...})` referenced by identifier in `tools: [mcp]`
resolves onto `AgentDef.ToolRefs`, not `HostedToolRefs`, so a hoisted binding
escapes this rule entirely, same as OAI-116.

---

### OAI-115: Agent wires a HostedMCPTool with no allowed_tools allow-list (Severity: high, Confidence: 0.7, Fix type: config)

**What we detect:** an OpenAI Agents SDK agent (`Agent` or `SandboxAgent`,
Python) whose `tools=[...]` includes a `HostedMCPTool(...)` whose `tool_config`
dict literal has no `allowed_tools` key. The match is
`agent_uses_hosted_tool_class: [HostedMCPTool]` AND NOT
`agent_hosted_tool_kwarg_present` with class `HostedMCPTool` and kwarg
`tool_config.allowed_tools`; the dotted path reads inside the dict literal.

**Why it is flaggable:** a `HostedMCPTool` is not a tool, it is a subscription
to a catalog. The Responses API connects the model to whatever the server at
`server_url` exposes at call time; the agent's source names a server, never
the tools. `allowed_tools` is the one static boundary a reviewer can check,
and without it the surface changes whenever the server is updated, on the far
side of a trust boundary the codebase does not control.

**Real-world consequence:** a server the team adopted for one tool later
exposes another. A documentation server that adds a write-capable tool, or a
compromised server that swaps a tool description for an instruction, reaches
the model as a new capability with no change on the agent side. The
description text is an instruction channel (LLM01) and the tool itself is
capability the agent was never designed to hold (LLM06).

**Why severity is high and not critical:** the boundary is set by a third
party and is unbounded, which is what puts it above medium. It stops short of
critical because the Python path keeps the API's default approval requirement:
a call to an unlisted tool still passes through an approval step unless the
author also set `require_approval` to never. The TypeScript sibling, OAI-116,
explains why that default matters.

**Fix type (config):** add `"allowed_tools": [...]` to the `tool_config` dict,
naming the tools the agent's task needs, and re-review the list when the task
changes. Keep `require_approval` at its default for anything side-effecting.

**Confidence 0.7:** the two facts are read from the constructor literal, so a
fire is not a guess, but the check is presence only. An allow-list that names
every tool counts as present, and a `tool_config` assembled elsewhere (a
variable or a helper) is not enumerable, so the rule fires on it even when the
assembled dict sets the allow-list. That unreadable case is the main false
positive and the reason the number is not higher.

---

### OAI-116: TypeScript agent wires a hostedMcpTool with no allowedTools allow-list (Severity: high, Confidence: 0.75, Fix type: config)

**What we detect:** a TypeScript OpenAI Agents SDK `Agent` whose `tools`
array includes a `hostedMcpTool({...})` whose options object sets no
`allowedTools`. The match is `agent_uses_hosted_tool_class: [hostedMcpTool]`
AND NOT `agent_hosted_tool_kwarg_present` with class `hostedMcpTool` and kwarg
`allowedTools`. A `{ toolNames: [...] }` filter object counts as present.

**Why it is flaggable:** the same catalog subscription as OAI-115, with one
sharper edge. `hostedMcpTool()` defaults `requireApproval` to never when the
option is omitted, so an agent that sets neither `allowedTools` nor
`requireApproval` has no static boundary and no runtime approval gate either.
Every tool the server exposes is callable, and every call executes without a
confirmation step.

**Real-world consequence:** a poisoned or newly added tool description reaches
the model unfiltered and the resulting call runs immediately. Where the Python
case leaves an approval prompt between the model and the side effect, this
case leaves nothing, so the first sign of a compromised server is the effect
of the call, not a request to approve it.

**Why severity is high and not critical:** the finding is the absence of a
boundary on a remote catalog, not proof that the catalog holds a dangerous
tool. High reflects that the agent's own author has no way to know what the
boundary contains; critical is reserved for a configuration that removes a
control the codebase demonstrably relies on.

**Fix type (config):** add `allowedTools: [...]` to the `hostedMcpTool({...})`
options, naming the tools the agent may call, and set `requireApproval`
explicitly for anything side-effecting rather than leaving the never default.

**Confidence 0.75:** slightly above OAI-115 because the TypeScript options are
a flat object literal at the call site in the common case, so the presence
check has fewer places to miss than the nested Python dict, and because the
never default means a fire more often describes the real exposure. The same
presence-only limits apply: an allow-list that names everything counts, and an
options object built elsewhere fires even when it sets the list.

---

## What this policy does not cover

- The *quality* of an `input_guardrail` that is present (OAI-106) — a no-op
  guardrail satisfies the rule without screening anything.
- The trustworthiness of the MCP server itself (pinning, auth, checksums) — both
  rules check for the control's presence, not the server's provenance.
- Tool poisoning that survives an `input_guardrail` (OAI-106) or an
  `allowed_tools` list that itself names a poisoned or too-broad tool
  (OAI-115) — a description crafted to pass the specific checks in place, or
  an allow-list padded wider than the task needs.
- `output_guardrails` gaps for MCP-fetched content (an egress concern; see
  agent_safety OAI-110 for the content-fetch output-guardrail rule).
- OAI-115 does not evaluate `require_approval` as its own condition — a
  Python `HostedMCPTool` with approval disabled *and* no allow-list is the
  most exposed combination the rule can see, and it fires the same as any
  other missing-allow-list case rather than at elevated severity. Python's
  benign platform-default fallback (approval-required when the key is
  omitted) means there is no equivalent TS-style verifiable-omission gap to
  build a parallel rule from — see the language-gating discussion above.
- OAI-117 does not fire on an *explicit* `requireApproval: 'never'` — only on
  omission. The two are byte-identical at the wire-payload level (verified
  in SDK source), but an explicit `'never'` is a reviewable, deliberate
  choice, and this policy's own OAI-116 fix guidance already tells authors
  to "set requireApproval explicitly" — flagging the explicit form would
  penalize following that advice. A rule on the explicit form, if ever
  added, is a distinct next rule (OAI-118), not a widening of OAI-117.
- Neither OAI-116 nor OAI-117 combines its check with the other's — an agent
  missing both `allowedTools` and `requireApproval` fires both findings on
  the same `hostedMcpTool(...)` call rather than one elevated finding. This
  is deliberate (see "What this policy covers" above): the two are distinct
  controls (catalog scope vs. runtime execution gate), and folding them into
  one finding would lose the ability to report a repo that has fixed only
  one of the two.
- OAI-116 does not resolve a hoisted `const mcp = hostedMcpTool({...})`
  referenced by identifier in `tools: [mcp]` — that shape lands on
  `AgentDef.ToolRefs`, not `HostedToolRefs`, so the rule never sees it. Only
  a `hostedMcpTool(...)` call written directly inline inside the `tools:`
  array is recognized.
- OAI-116 does not capture a `hostedMcpTool({...})` options object built from
  a variable or a `...spread` rather than an object literal — `TSObjectKwargs`
  only descends into a literal `object` node, so such a call is treated as
  having no kwargs and fires even if `allowedTools` is in fact set
  dynamically.
- The content of an allow-list. OAI-115 and OAI-116 check that `allowed_tools`
  or `allowedTools` is present, not that it is narrow: a list that names every
  tool the server has satisfies them.
- A `tool_config` dict or options object assembled outside the call. The
  predicate reads the literal at the call site, so a boundary set through a
  variable or helper is invisible and the rule fires anyway.

---

## Recommendations beyond the fix

```python
from agents import Agent, input_guardrail, GuardrailFunctionOutput

@input_guardrail
def screen_mcp(ctx, agent, user_input) -> GuardrailFunctionOutput:
    # Inspect user_input AND the resolved tool list for poisoned descriptions.
    if _looks_poisoned(agent.tools):
        return GuardrailFunctionOutput(tripwire_triggered=True,
                                       output_info="suspicious MCP tool description")
    return GuardrailFunctionOutput(tripwire_triggered=False, output_info="")

agent = Agent(name="research", mcp_servers=[trusted_server],
              input_guardrails=[screen_mcp])
```

1. Add an `input_guardrail` that screens both the user input and the resolved MCP
   tool list before the model runs.
2. Pin MCP servers to known-trusted URLs and verify checksums/signatures where the
   transport allows; treat an unpinned remote MCP server as untrusted input.
3. Pair with `output_guardrails` so data the model tries to send back out through an
   MCP tool argument is inspected before egress.
S
For the hosted path (`HostedMCPTool`), pin the inherited catalog to a named
allow-list instead:

```python
from agents import Agent, HostedMCPTool

agent = Agent(
    name="research",
    tools=[
        HostedMCPTool(
            tool_config={
                "type": "mcp",
                "server_label": "deepwiki",
                "server_url": "https://mcp.deepwiki.com/mcp",
                "allowed_tools": ["ask_question"],
            }
        )
    ],
)
```

4. Add `allowed_tools` to every `HostedMCPTool`'s `tool_config`, naming only
   the tools this agent's task actually needs; re-review the list whenever
   the task changes.
5. Keep `require_approval` at its SDK default (`"always"`) for anything
   side-effecting, rather than `"never"` — the allow-list bounds *which*
   tools are reachable, `require_approval` bounds *whether each call*
   executes without a human in the loop; the two are complementary, not
   substitutes for each other.

The TypeScript SDK is the same fix, flat options instead of a nested dict —
and here `requireApproval` needs to be set explicitly, since omitting it does
not fall back to a safer default the way Python's does:

```ts
import { Agent } from "@openai/agents";
import { hostedMcpTool } from "@openai/agents-core";

export const research = new Agent({
  name: "research",
  instructions: "Answer questions using the deepwiki MCP server",
  tools: [
    hostedMcpTool({
      serverLabel: "deepwiki",
      serverUrl: "https://mcp.deepwiki.com/mcp",
      allowedTools: ["ask_question"],
      requireApproval: "always",
    }),
  ],
});
```

6. Add `allowedTools` to every `hostedMcpTool({...})` call, naming only the
   tools this agent's task actually needs.
7. Set `requireApproval` explicitly rather than leaving it unset — an omitted
   `requireApproval` is not a safe default in this SDK, it is silently
   rewritten to `'never'` inside `hostedMcpTool` itself.
