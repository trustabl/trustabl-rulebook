---
policy_id: nvidia_nat_agent_safety
category: nvidia_nat
topic: agent_safety
rules:
  - id: NAT-102
    severity: low
    confidence: 0.6
    scope: agent
    fix_type: config
  - id: NAT-103
    severity: low
    confidence: 0.6
    scope: agent
    fix_type: config
  - id: NAT-104
    severity: low
    confidence: 0.8
    scope: agent
    fix_type: config
references: [LLM02, LLM10]
---

# Policy Rationale: NeMo Agent Toolkit Agent Safety

**Policy ID:** `nvidia_nat_agent_safety`  
**File:** `nvidia_nat/agent_safety.yaml`  
**Rules:** NAT-102, NAT-103, NAT-104  
**Severities:** low, low, low  
**Fix types:** config, config, config  
**References:** LLM02 (Sensitive Information Disclosure), LLM10 (Unbounded Consumption)

---

## What this policy covers

Agent-scope rules for NVIDIA NeMo Agent Toolkit (NAT) workflow configs. A NAT
agent is not a constructor call — it is a YAML block: the config's `workflow:`
section carrying `_type: react_agent` or `_type: tool_calling_agent`, or an
agent-typed entry nested under `functions:` (the pattern NVIDIA's own docs use
for a `math_agent` wrapped as a tool). Discovery parses that block's fields
into the same kwarg tree every other agent-scope predicate reads, so these
rules query the config file's own keys: an iteration cap left to the framework
default (`max_tool_calls` on the ReAct agent, NAT-102; `max_iterations` on the
tool-calling agent, NAT-103), and `verbose: true` (NAT-104), the flag NVIDIA's
own field reference warns logs the agent's input, output, and intermediate
steps. The `nat_react_agent` applies-to token covers the `per_user_react_agent`
variant too — same config surface, same fields, one rule.

Because the agent *is* a config file, NAT agent rules carry no `language:`
field — YAML has no source language, for the same reason the subagent and
skill scopes carry none — and the detector does not gate on language.

---

## Why agent configuration is a distinct concern in NAT workflows

NAT inverts the shape every code-first SDK uses: the entire agent — its tools,
its LLM, its loop bounds, its logging posture — is declared in a YAML document
that is typically copied from a vendor example and edited by hand. There is no
type checker, no linter, and no code review convention watching these files,
so a field that was never set, or a flag an example left on, ships exactly as
the scaffold had it. Two threat lines run through this policy.

The **unbounded-consumption line** (OWASP LLM10, rules NAT-102/103): both
agent loops iterate until the model produces a final answer or a cap stops
them. NVIDIA documents the cap on each agent — `max_tool_calls`: "Defaults to
`15` … the maximum amount of tool calls the agent may take before answering
the original question" (ReAct agent reference), and `max_iterations`:
"Defaults to 15. The maximum number of tool calls the agent may perform"
(tool-calling agent reference) — and its ReAct limitations section is explicit
about the cost mechanism: reasoning between steps "can lead to multiple LLM
calls per task, increasing latency and API costs." The framework default
prevents a true runaway, but it is a generic ceiling rather than one sized to
the agent's role: a model that loops or oscillates burns the full budget of
tool round-trips — each with an LLM reasoning call around it — before the
toolkit forces the canned failure answer ("could not produce a final answer
within N iterations"). The implicit default is also a moving target: it lives
in the toolkit, not the config, so a version bump can shift the bound the
agent actually runs under without any change in the scanned file. This is the
same framing as CrewAI's CREW-110 (crewai/agent_safety.md), applied to a
config key instead of a constructor kwarg.

The **confidentiality line** (OWASP LLM02, rule NAT-104): `verbose` is the one
field where NVIDIA's documentation states the security rationale in the field
doc itself — "Defaults to `False` (useful to prevent logging of sensitive
data). If set to `True`, the agent will log input, output, and intermediate
steps." The toolkit's Security Considerations page devotes a whole section to
why that matters: "User inputs, API responses, and intermediate results may
contain sensitive, personal, confidential, or regulated information", "API
keys, tokens, or credentials may be written to log files", and — the subtle
one — logs "may inadvertently violate access control on source data, including
… data collected and inserted into prompts by tools, such as an MCP tool, that
use delegated authorization from the user." Process logs outlive the
conversation: aggregation ships them off-host, retention keeps them for
months, and their access-control list is the ops team's, not the source
system's. And the flag is not an exotic misconfiguration — it is the vendor's
own scaffold: both configuration examples in NVIDIA's agent docs set
`verbose: true`, and in the upstream repository 107 example configs ship
`verbose: true` against 3 that set it false. A workflow scaffolded from any
example carries the dev-mode flag into production unless someone deliberately
deletes the line. That prevalence is the finding's point, and the confidence
number owns it below.

---

## Rule-by-rule defense

### NAT-102 — react_agent has no explicit max_tool_calls limit (Severity: low, Confidence: 0.6, Fix type: config)

**What we detect:**  
An agent block whose `_type` is `react_agent` or `per_user_react_agent`
(applies-to `nat_react_agent`) where the `max_tool_calls` key is absent from
the block, or present with a literal null (predicate `agent_kwarg_missing`).
Discovery captures the YAML block's fields verbatim as the kwarg tree, so the
predicate is a direct key lookup on the config.

**Why it is flaggable:**  
With no explicit cap the agent falls back to the toolkit default —
`max_tool_calls: int = Field(default=15, …)` in the ReAct agent's registration,
documented as "Defaults to `15`". A ReAct agent reasons between every tool
call (Observation → Thought → Action → repeat), so each budgeted iteration is
a tool round-trip *plus* an LLM call, and NVIDIA's own limitations section
flags exactly this: step-by-step reasoning "can lead to multiple LLM calls per
task, increasing latency and API costs." The default prevents a true runaway
but is sized for nobody: a single-lookup agent that should stop after two
calls gets fifteen, and because the number lives in the toolkit rather than
the config, a toolkit upgrade can move it silently.

**Real-world consequence:**  
- A `wikipedia_search` agent gets an ambiguous question, oscillates between
  re-querying and re-reasoning, and burns 15 tool calls with an LLM call
  around each — a sub-second lookup becomes a multi-minute, multi-dollar
  workflow step, once per request.
- When the cap finally trips, the user receives the toolkit's canned failure
  text ("could not produce a final answer within 15 iterations") — after the
  full budget was spent, not before.
- If any tool in `tool_names` has side effects (a ticket comment, a write
  through an MCP client), the loop emits the side effect once per iteration.

**Why severity is low and not medium:**  
The framework default already terminates the loop with no developer action, so
this is not an unbounded runaway — it flags a missing *explicit, role-sized*
cap, a cost-and-latency hygiene nudge. Nothing here grants the model a
capability it did not have; the worst case is bounded waste and a degraded
answer. That is the same calibration as CREW-110, and for the same reason.

**Fix type — config:**  
The fix is one YAML key in the agent block (`max_tool_calls: 5`) — no tool or
workflow code changes.

**Confidence 0.6:**  
The predicate is a presence check on a single key, and four things sit outside
that read. First, the alias false positive: the ReAct agent's config model
declares `validation_alias=AliasChoices("max_tool_calls", "max_iterations")`,
so a react_agent bounded via `max_iterations: 5` is validly capped — but
discovery captures keys verbatim with no alias normalization, so the rule
fires anyway. Second, the check is presence-only: `max_tool_calls: 9999`
satisfies it while bounding nothing. Third, bounds the rule cannot see — the
retry caps (`parse_agent_response_max_retries`, `tool_call_max_retries`), an
external timeout on the caller, or a reasoning wrapper that plans the tool
sequence up front — can make the config safe in practice while it still fires.
Fourth, a `nat run --override workflow.max_tool_calls 5` in a deployment
script caps the agent outside the file, invisibly to a scan of the file. Those
over-flags hold it at 0.6 rather than the 0.8 the literal-value rule below
carries.

### NAT-103 — tool_calling_agent has no explicit max_iterations limit (Severity: low, Confidence: 0.6, Fix type: config)

**What we detect:**  
An agent block whose `_type` is `tool_calling_agent` (applies-to
`nat_tool_calling_agent`) where the `max_iterations` key is absent, or present
with a literal null (predicate `agent_kwarg_missing`).

**Why it is flaggable:**  
Same mechanism as NAT-102 on the sibling agent: NVIDIA documents
`max_iterations` as "Defaults to 15. The maximum number of tool calls the
agent may perform", and the registration declares `default=15`. The
tool-calling agent adds one interaction that makes the cap worth sizing
deliberately: `handle_tool_errors` defaults to `True`, and NVIDIA documents it
as catching every tool error and returning a `ToolMessage` "allowing the agent
to retry" — so a persistently failing tool does not raise, it silently
consumes iterations until the implicit bound is reached. A tight, explicit cap
is what converts that retry loop from fifteen quiet failures into a fast,
visible one.

**Real-world consequence:**  
- A weather tool's API key expires; every call errors, `handle_tool_errors`
  feeds the error back, and the model retries the same call 15 times before
  returning the canned "could not produce a final answer within 15 iterations"
  message — per request, for as long as the key stays broken.
- A model that alternates between two tools without converging burns the full
  default budget of tool calls and LLM turns on every invocation of the
  workflow.

**Why severity is low and not medium:**  
Identical defense to NAT-102: the framework default already bounds the loop,
so the finding is a missing role-sized cap, not a runaway. The tool-calling
agent is also the cheaper of the two loops — it does not reason between calls
— so the per-iteration waste is smaller than the ReAct case.

**Fix type — config:**  
One YAML key in the agent block (`max_iterations: 5`), pairing naturally with
the `handle_tool_errors` setting already in the same block.

**Confidence 0.6:**  
Presence-only, like its sibling: `max_iterations: 9999` passes while bounding
nothing. The rule cannot see external bounds — a caller-side timeout, a
front-end request budget, or a `--override` supplied at run time. One
NAT-specific over-flag: a config whose tools are all listed in
`return_direct` returns each tool's output immediately without further agent
processing, so the loop bound is close to irrelevant for those flows, yet the
rule still fires. (Unlike NAT-102 there is no alias gap — the tool-calling
config declares `max_iterations` with no `AliasChoices` — which is why the two
rules read different keys in the first place.)

### NAT-104 — Agent runs with verbose logging of prompts and outputs (Severity: low, Confidence: 0.8, Fix type: config)

**What we detect:**  
An agent block of either type (applies-to `nat_react_agent`,
`nat_tool_calling_agent`) carrying `verbose: true` (predicate
`agent_kwarg_value` with kwarg `verbose`, value `"true"`). Discovery
canonicalizes YAML booleans to lowercase text, so `true`, `True`, and `TRUE`
all match one spelling.

**Why it is flaggable:**  
This is the rare rule whose grounding is the vendor's own field doc, verbatim:
"`verbose`: Defaults to `False` (useful to prevent logging of sensitive
data). If set to `True`, the agent will log input, output, and intermediate
steps." NVIDIA shipped the default as `False` *for a stated security reason*,
and this config overrides it. Under the hood the flag becomes `detailed_logs`
on the agent graph, so everything that flows through the loop — the user's
prompt, retrieved documents, every tool result, a credential a tool echoes —
is written to the process logs. NVIDIA's Security Considerations page
enumerates the resulting damage class in its logging section: sensitive data
in logs, credential logging, retention beyond need, and log access
"inadvertently violat[ing] access control on source data", including data an
MCP tool fetched under the user's delegated authorization. The log pipeline is
a second copy of the conversation with a different — usually wider — audience
and a much longer lifetime.

**Real-world consequence:**  
- A support workflow's user pastes an API key into their question; verbose
  logging writes the full prompt and every intermediate step to stdout, the
  log shipper forwards it to the aggregator, and the key sits in a 90-day
  retention window readable by everyone with log access — none of whom could
  read the source system.
- An agent whose MCP tool fetches a customer record under delegated auth logs
  that record's contents as an intermediate step, republishing per-user data
  into a store with no per-user access control — the exact scenario NVIDIA's
  logging-security bullet names.

**Why severity is low and not medium:**  
The flag grants the model nothing and opens no attack path — exploitation
requires an adversary (or an over-permissioned insider) who already reads the
log sink, and the damage is disclosure of data the workflow was legitimately
processing. Many flagged configs are genuinely development-stage, where
verbose output is the point. What keeps it a finding at all is the ratchet:
logs persist, aggregate, and outlive the deployment posture the config was
written for. A low-severity, one-line-deletion finding is the honest weight.

**Fix type — config:**  
Delete the line — the default is `False`, and NVIDIA's own doc gives the
reason. If step-level observability is the goal, the config's
`general.telemetry.tracing` section is the purpose-built channel and can point
at a store with deliberate retention and access control.

**Confidence 0.8:**  
The match itself is unambiguous — a literal field read with canonicalized
spelling — so the 0.2 gap is not detection uncertainty; it is context the rule
cannot see, and the dominant piece is prevalence, owned here honestly: **every
vendor example ships `verbose: true`** — both configuration snippets in
NVIDIA's agent docs, and 107 of the upstream repository's example configs
against 3 that set it false — so this rule fires on virtually every
example-scaffolded repo, including real dev sandboxes where verbose is
appropriate. That over-flagging is deliberate: the dev-mode default carried
unmodified into production *is* the finding, and the rule cannot distinguish a
scratch config from a production one. Other false positives: a workflow that
processes no sensitive data, or a log pipeline that already scrubs and
access-controls its sink. False negatives run the other way: Pydantic coerces
`verbose: yes` or `verbose: on` to `True`, but the YAML parser tags those as
strings, not booleans, so they escape the canonicalized `"true"` match; a
templated value (`verbose: ${VERBOSE}`) is opaque to the scan; and a
`nat run --override workflow.verbose true` flips the flag outside the file
entirely.

---

## What this policy does not cover

- **Cap values are not judged.** NAT-102/103 are presence-only:
  `max_tool_calls: 9999` or `max_iterations: 500` satisfies the rule while
  providing no meaningful bound.
- **The ReAct alias fires as a known false positive.** `max_iterations:` is a
  valid Pydantic alias for `max_tool_calls` on the react_agent config;
  discovery captures keys verbatim, so a react_agent capped via the alias
  still trips NAT-102.
- **Runtime overrides are invisible in both directions.** NAT's CLI accepts
  `--override` with dot notation, so a deployment script can cap an uncapped
  config (NAT-102/103 over-flag) or switch verbose on for a clean one
  (NAT-104 miss) without touching the scanned file.
- **Non-canonical booleans escape NAT-104.** `verbose: yes` / `verbose: on`
  are coerced to `True` by the toolkit's config model but are strings to the
  YAML parser, so they do not match the canonical `"true"`; templated values
  (`${VERBOSE}`) are likewise opaque.
- **Only three agent `_type`s are promoted to agents.** `react_agent`,
  `per_user_react_agent`, and `tool_calling_agent` are the closed v1 set; a
  ReWOO agent, reasoning agent, router agent, or custom registered agent type
  is discovered as part of the config but fires no agent-scope rule, whatever
  its caps or verbosity.
- **Other consumption bounds go unread.** The retry caps
  (`parse_agent_response_max_retries`, `tool_call_max_retries`),
  `max_history`, the derived LangGraph `recursion_limit`, and any bound
  enforced by the caller are outside the predicates, so an externally bounded
  workflow is a deliberate over-flag.
- **Verbose is judged per agent block, and only that flag.** Telemetry
  exporters or front-end logging that capture the same prompts and outputs
  through a different channel leak identically without firing NAT-104 — the
  fix satisfies the rule without guaranteeing the logs are clean.
- **The rest of the NAT surface lives elsewhere.** Unfiltered `mcp_client`
  tool wiring, the unauthenticated SSE transport, and a `code_execution`
  function with no guardrails middleware are NAT-101/105/106 in
  [nvidia_nat/mcp.md](mcp.md), not here.

---

## Recommendations beyond the fix

```yaml
# Safe shape: explicit, role-sized caps; verbose left at its secure default;
# observability through telemetry, not raw agent logs.
general:
  telemetry:
    tracing:
      otel:
        _type: otelcollector          # a store you control, with retention
        endpoint: http://otel:4317    # and access policy set deliberately

llms:
  nim_llm:
    _type: nim
    model_name: meta/llama-3.1-70b-instruct

workflow:
  _type: react_agent
  tool_names: [wikipedia_search, current_datetime]
  llm_name: nim_llm
  max_tool_calls: 5                   # explicit — not the toolkit's implicit 15
  tool_call_max_retries: 1
  parse_agent_response_max_retries: 1
  # verbose omitted: defaults to false —
  # "useful to prevent logging of sensitive data" (NVIDIA field reference)

functions:
  math_agent:
    _type: tool_calling_agent
    tool_names: [calculator]
    llm_name: nim_llm
    description: 'Useful for performing simple mathematical calculations.'
    max_iterations: 3                 # sized to the role: one calculation
    handle_tool_errors: true          # errors surface as results, not iterations
```

1. Size each cap to the role and treat hitting it as a signal, not a bound to
   raise: the toolkit's "could not produce a final answer within N iterations"
   answer is a detectable string — alert on it, and split genuinely long tasks
   into bounded sub-workflows instead of removing the ceiling.
2. Set the cap in *every* config profile, dev included — configs are copied
   between profiles, and the toolkit default can move between releases, so
   only an explicit value pins the bound the agent actually runs under.
3. Keep the ReAct retry caps (`parse_agent_response_max_retries`,
   `tool_call_max_retries`) at their tight defaults — NVIDIA documents them as
   preventing "infinite hallucination loops" and "infinite tool call loops" —
   and use `return_direct` on the tool-calling agent for tools whose output
   needs no further agent processing.
4. If step-level visibility is the goal, use `general.telemetry.tracing`
   pointed at a store with deliberate retention and RBAC, and apply the
   controls NVIDIA's Security Considerations page lists for logs: sanitization
   before write, secret scanning, encryption, and access control on the sink.
5. Audit deployment scripts for `--override` usage — a flag flipped at run
   time bypasses both this scan and the config review, in either direction.
