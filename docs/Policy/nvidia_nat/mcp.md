---
policy_id: nvidia_nat_mcp
category: nvidia_nat
topic: mcp
rules:
  - id: NAT-101
    severity: high
    confidence: 0.75
    scope: agent
    fix_type: config
  - id: NAT-105
    severity: medium
    confidence: 0.6
    scope: agent
    fix_type: config
  - id: NAT-106
    severity: medium
    confidence: 0.6
    scope: repo
    fix_type: config
references: [LLM01, LLM03, LLM05, LLM06]
---

# Policy Rationale: NeMo Agent Toolkit MCP and Code-Execution Wiring

**Policy ID:** `nvidia_nat_mcp`  
**File:** `nvidia_nat/mcp.yaml`  
**Rules:** NAT-101, NAT-105, NAT-106  
**Severities:** high, medium, medium  
**Fix types:** config, config, config  
**References:** LLM01 (Prompt Injection), LLM03 (Supply Chain), LLM05 (Improper Output Handling), LLM06 (Excessive Agency)

---

## What this policy covers

The surfaces a NeMo Agent Toolkit (NAT) workflow config wires in from *outside*
the repository. In NAT the agent is not a constructor call but a YAML block — a
`workflow:` (or nested `functions:`) entry whose `_type` is `react_agent` /
`tool_calling_agent` — and the toolkit's MCP client is a `function_groups:`
entry of `_type: mcp_client` or `per_user_mcp_client` that, per NVIDIA's own
documentation, lets you "connect to an MCP server, dynamically discover the
tools it serves, and register them as NeMo Agent Toolkit functions"
([mcp-client.md](https://github.com/NVIDIA/NeMo-Agent-Toolkit/blob/main/docs/source/build-workflows/mcp-client.md)).
Two agent-scope rules read the resolved `mcp_client` group subtree off the
agent's hosted-tool refs: NAT-101 fires when neither `include:` nor `exclude:`
narrows the discovered catalog, and NAT-105 fires when `server.transport` is
`sse`, a transport the toolkit documents as unauthenticatable. One repo-scope
rule, NAT-106, reads the components config discovery emits for the whole repo:
a `functions:` entry of `_type: code_execution` with no `guardrails` middleware
and no recognizable HITL middleware declared anywhere. Because the agent *is* a
config file, NAT agent rules carry no `language:` — the same reason the
subagent and skill scopes carry none — and the detector does not gate on
language.

---

## Why externally-wired capability is a distinct concern in NAT workflows

Everything else in a NAT config is enumerable by reading the YAML: a
`functions:` entry names a registered tool type, `tool_names:` lists exactly
what the agent may call, and a reviewer can bound the agent's capability from
the file alone. The three surfaces in this policy break that property — each
one delegates part of the agent's capability boundary to something outside the
repository, and the config is the only place a reviewer can pull it back in.

An unfiltered `mcp_client` group (NAT-101) hands the agent whatever tool
catalog the remote MCP server exposes *at connect time*. NVIDIA's docs are
explicit that the group "provides all accessible tools from the MCP server to
the workflow" and that "the function group supports filtering using the
`include` and `exclude` parameters" — filtering is the toolkit's only
mechanism for pinning that catalog to a reviewed allow-list. Without it, a
server-side update or compromise widens the agent's agency with no reviewable
diff in this repo (the LLM03 supply-chain edge of LLM06 excessive agency), and
a poisoned tool *description* in the inherited catalog is injection payload
the model reads on every turn (LLM01). This is the exact threat shape of
Google ADK's `MCPToolset` with no `tool_filter=` — see
[ADK-111](../google_adk/agent_safety.md) — transposed from a Python
constructor kwarg to a YAML group.

The SSE transport (NAT-105) breaks the boundary at the wire instead of the
catalog. NVIDIA's MCP server guide carries a warning box titled "SSE Transport
Security Limitations": "The SSE transport does not support authentication. For
production deployments, use `streamable-http` transport with authentication
configured. SSE should only be used for local development on localhost or
behind an authenticating reverse proxy"
([mcp-server.md](https://github.com/NVIDIA/NeMo-Agent-Toolkit/blob/main/docs/source/run-workflows/mcp-server.md)).
The client side matches: `server.auth_provider` is documented as "only
supported with `streamable-http` transport", so an SSE connection is
*structurally* unauthenticatable from this config — no field exists that could
fix it. Whoever can reach or impersonate the endpoint serves this agent's
tools and reads every argument the agent sends (LLM03, with an LLM02-shaped
leak on the side).

The `code_execution` function (NAT-106) is the widest capability a config can
grant: per NVIDIA's docs it "sends a string of python code to a remote code
execution server where code is executed" — model-written code, verbatim, to an
executor (LLM05 improper output handling on top of LLM06). The toolkit's own
mitigation surfaces are middleware: the `guardrails` middleware "hosts NeMo
Guardrails as a policy engine at function input and output boundaries"
([middleware.md](https://github.com/NVIDIA/NeMo-Agent-Toolkit/blob/main/docs/source/build-workflows/advanced/middleware.md)),
and `HITLMiddleware` is the base for "intercept patterns that require a human
decision before or after a function call". With neither declared, the only
bound on model-written code is whatever the sandbox container permits —
NVIDIA's own security-considerations doc lists "Command execution" under tool
abuse and names guardrails and sandboxing as the example mitigations.

All three fixes are *config* — YAML edits to the workflow file, no tool source
code involved.

---

## Rule-by-rule defense

### NAT-101 — Agent wires an mcp_client group with no include or exclude filter (Severity: high, Confidence: 0.75, Fix type: config)

**What we detect:**  
An agent block (`nat_react_agent` / `nat_tool_calling_agent`) whose
`tool_names:` references a `function_groups:` entry of `_type: mcp_client` or
`per_user_mcp_client` (`agent_uses_hosted_tool_class`), where no such group on
the agent carries an `include:` or `exclude:` key (negated
`agent_hosted_tool_kwarg_present` over both kwargs and both classes).
Discovery attaches the group's whole YAML subtree as the hosted ref's resolved
kwargs, so the presence check reads the actual config keys, not a text match.

**Why it is flaggable:**  
Every other `tool_names:` entry names a capability the author chose,
enumerable by reading the config. An unfiltered `mcp_client` group is the one
entry that does not: NVIDIA's docs say it will "dynamically discover the tools
it serves" and "provides all accessible tools from the MCP server to the
workflow" — a set decided by the server operator, invisible in this repo, and
free to grow or change meaning whenever the server updates. `include`/`exclude`
is the toolkit's only mechanism for narrowing that catalog to a reviewed
allow-list; without one there is no static boundary a code reviewer, a diff,
or this scanner can check.

**Real-world consequence:**  
- A workflow wired to a filesystem MCP server "for read-only summarization"
  inherits `write_file` and `delete_path` the day the server ships them — no
  config change, no redeploy, nothing for review to catch.
- A compromised or rug-pulled server adds a tool whose *description* carries
  an injection payload (tool poisoning); the model reads every description in
  the inherited catalog on every reasoning turn.
- Pair the inherited surface with any injection path already in the loop
  (retrieved content, another tool's output) and the injected instruction has
  a strictly larger tool menu than the author ever saw.

**Why severity is high and not critical (or medium):**  
Not critical, because the finding proves inherited *breadth*, not inherited
*danger* — whether the catalog contains a destructive tool depends on the
server, and the tools still execute server-side under whatever authorization
the server enforces. Not medium, because the failure is structural rather than
situational: the agent's capability boundary is delegated to a remote party
and can move without any change in the scanned repo, silently converting
every server update into an ungated capability grant — the defining LLM06
shape, with an LLM03 supply-chain edge. This is the calibration ADK-111
carries for the identical pattern (`MCPToolset` with no `tool_filter=`), and
the two rules are deliberately pinned to the same high/0.75.

**Fix type — config:**  
Add `include:` (preferred — it fails closed as the server grows; `exclude`
fails open) to the group's YAML block. A config-file edit, no code.

**Confidence 0.75:**  
The gap is dominated by the predicate's any-quantification, the same
imprecision ADK-111 documents: the filter check is per *agent*, not per
*group*, so one filtered `mcp_client` group beside one unfiltered sibling on
the same agent silences the rule for both — and because the negated `any:`
spans both classes, an `include:` on a `per_user_mcp_client` group even
credits an unfiltered plain `mcp_client` group on the same agent. The check is
also presence-only: an `include:` naming every tool the server serves, or an
`exclude:` naming nothing that matters, satisfies the rule while narrowing
nothing. In the false-positive direction, a group whose `server.transport` is
`stdio` runs a locally-launched, version-pinnable server process, so the
"outside the repository" premise is weaker there — the rule still fires
because the catalog is still discovered dynamically. False negative: a
`tool_names` entry using the dotted `<group>__<tool>` form does not resolve to
the group and is not classified as a hosted ref at all — benign in practice,
since NVIDIA documents that form as requiring the tool to be "explicitly
listed under the optional `include` list" anyway. Unlike ADK-111 there is no
unresolved-constructor asymmetry: the group subtree lives in the same YAML
document, so the kwargs are always resolved.

### NAT-105 — mcp_client connects over SSE, a transport with no authentication (Severity: medium, Confidence: 0.6, Fix type: config)

**What we detect:**  
An agent whose `mcp_client` or `per_user_mcp_client` group sets the dotted
config path `server.transport` to the literal `sse`
(`agent_hosted_tool_kwarg_value` navigating the resolved group subtree; a
quoted `"sse"` is quote-stripped before comparison).

**Why it is flaggable:**  
This is NVIDIA's own warning, made a finding. The toolkit's MCP server doc
states: "The SSE transport does not support authentication. For production
deployments, use `streamable-http` transport with authentication configured.
SSE should only be used for local development on localhost or behind an
authenticating reverse proxy." The client doc closes the loop:
`server.auth_provider` is "only supported with `streamable-http` transport",
and SSE itself is "maintained for backwards compatibility" with the
recommendation to use `streamable-http` instead. So an SSE connection is not
merely *unauthenticated* — it is *unauthenticatable* from this config: there
is no field the author could add to fix it without changing transport.

**Real-world consequence:**  
- The config is promoted from a dev laptop to a shared environment unchanged;
  the SSE URL now points at a reachable host, and anyone on the network path
  can impersonate the server — serving this agent's entire tool catalog,
  poisoned descriptions included, and reading every argument the agent sends.
- Because SSE URLs in NVIDIA's examples are plain `http://`, the channel is
  typically unencrypted as well as unauthenticated: tool arguments carrying
  user data transit in the clear.

**Why severity is medium and not high (or low):**  
Not high, because the exposure is conditional on where the endpoint lives:
NVIDIA explicitly sanctions SSE "for local development on localhost or behind
an authenticating reverse proxy", and in those two postures the finding is a
hygiene note, not a hole. Not low, because when the precondition fails —
a routable URL, no proxy — the consequence is total: the party who reaches
the endpoint controls the agent's tools, which is a supply-chain compromise
(LLM03) of the whole workflow, not a degraded feature.

**Fix type — config:**  
Change `server.transport` to `streamable-http` and add `server.auth_provider`
— two YAML keys on the group block.

**Confidence 0.6:**  
The gap is owned almost entirely by the false positive NVIDIA's own guidance
creates: a localhost-dev SSE config is *statically indistinguishable* from a
production one. The rule reads `transport: sse` but cannot know whether the
URL will only ever resolve on a developer loopback, and it does not read the
`server.url` value at all — so `url: http://localhost:8080/sse`, the exact
shape NVIDIA's docs bless for development, fires identically to
`url: http://mcp.internal:8080/sse`. The sanctioned reverse-proxy deployment
is equally invisible: an authenticating proxy in front of the SSE endpoint
satisfies NVIDIA's guidance while the config still fires. False negatives:
a transport value supplied through interpolation or any non-scalar node is
not matched, and a config that omits `transport` defaults to
`streamable-http`, which is correctly silent.

### NAT-106 — code_execution function configured with no guardrails middleware (Severity: medium, Confidence: 0.6, Fix type: config)

**What we detect:**  
Repo scope. Config discovery emits a component for every `functions:` entry of
`_type: code_execution` (`nat_code_execution_function`), for every
`middleware:` entry of `_type: guardrails` (`nat_guardrails_middleware`), and
for every `middleware:` entry carrying a `pre_invoke_prompt` or
`post_invoke_prompt` key — the HITL base-config shape — as
`nat_hitl_middleware`. The rule fires when the repo contains a
`code_execution` component and neither middleware component
(`repo_component_present` with a negated `any:`).

**Why it is flaggable:**  
NVIDIA's docs describe `code_execution` plainly: "This function sends a string
of python code to a remote code execution server where code is executed."
Model-written code is the widest tool an agent can hold — whatever the
execution sandbox permits, a prompt-injected or simply wrong model can do
(LLM05 feeding LLM06). The toolkit's own answer to that width is middleware:
the `guardrails` middleware "hosts NeMo Guardrails as a policy engine at
function input and output boundaries" — input rails on `pre_invoke` see the
code string before it ships to the executor — and HITL middleware exists
precisely for "intercept patterns that require a human decision before or
after a function call". A repo that declares the capability and neither
mitigation has, statically, nothing between the model and the executor except
the executor itself.

**Real-world consequence:**  
- A ReAct agent with `code_execution` in its `tool_names` is prompt-injected
  through a retrieved document; the injected "write and run this snippet"
  request ships straight to the sandbox, which happily executes an
  exfiltration attempt bounded only by the container's network policy.
- No approval step exists to catch the model doing something merely wrong:
  a buggy generated script consumes the sandbox's resources or emits garbage
  that flows onward as trusted tool output.

**Why severity is medium and not high:**  
The capability is sandboxed by construction — the function ships pointing at
a remote executor (the bundled `local_sandbox` container or a Piston server),
and only `stdout` returns, so the finding flags a missing defense-in-depth
policy layer in front of a contained capability, not unmediated host
execution. That is one tier less severe than a shell on the agent's own
process. It stays medium rather than low because the sandbox bounds *where*
code runs, not *what the model is allowed to attempt* — the container's real
isolation (network egress, mounted volumes) is deployment-specific and
invisible to this scan, and NVIDIA's security guidance treats guardrails and
sandboxing as complementary layers, not alternatives.

**Fix type — config:**  
Declare a `middleware:` entry of `_type: guardrails` and attach it to the
`code_execution` function via its `middleware:` list (or gate it behind a
HITL middleware) — YAML only.

**Confidence 0.6:**  
The 0.6 owns three honest gaps. First, the mandated HITL caveat: NVIDIA's
`HITLMiddleware` is abstract — "concrete subclasses must declare their own
`name` to be runnable", so a custom HITL middleware's YAML shows only its
custom `_type`, which is not statically recognizable. Only the base-config
shape (a `pre_invoke_prompt` / `post_invoke_prompt` key in the middleware
block) is; a repo whose custom-typed HITL gate keeps its prompts in code
false-positives at exactly this confidence, and the fix text says so — the
finding is then a prompt to make the mitigation visible in review, not to add
a second one. Second, the check is presence-only and repo-wide, not an
attachment check: a `guardrails` middleware declared in *any* config silences
the rule even when it sits in a different workflow file than the
`code_execution` entry, is attached to unrelated functions, or is declared
and never referenced in any `middleware:` list at all — false negatives the
component model cannot see. Third, in the other direction, a `code_execution`
entry that no workflow's `tool_names` actually wires still fires (component
emission is per declaration, not per use), and mitigations living outside the
toolkit — a fully egress-blocked sandbox network, an external approval system
— are invisible, so a genuinely defended repo can still fire.

---

## What this policy does not cover

- The *quality* of a filter that is present — an `include:` listing every
  server tool, or an `exclude:` naming nothing that matters, satisfies
  NAT-101 while narrowing nothing; and even a tight `include` constrains
  *names* only — the server still controls what the allowed names do.
- The per-agent quantification of NAT-101: one filtered group silences the
  rule for an unfiltered sibling group on the same agent, across both
  `mcp_client` and `per_user_mcp_client`.
- `tool_overrides` poisoning-mitigation is not credited: overriding inherited
  descriptions reduces the tool-poisoning surface but does not satisfy
  NAT-101, and its absence is not flagged.
- NAT-105 does not read `server.url`, so it cannot suppress on localhost or
  escalate on a routable host; nor can it see an authenticating reverse proxy
  in front of an SSE endpoint (NVIDIA-sanctioned, still fires).
- The `stdio` transport is not examined at all — a stdio `mcp_client`
  launching an unpinned server via `npx`/`docker` is a real supply-chain
  surface this policy does not reach.
- NAT-106 checks declaration, not attachment: it cannot verify the guardrails
  middleware is actually listed in the `code_execution` function's
  `middleware:` list, that it is `enabled: true`, or that its rails do
  anything — a policy that always passes satisfies the rule while gating
  nothing.
- Custom middleware that mitigates by another name — a validation middleware
  with its own `_type`, or a custom HITL subclass whose YAML carries neither
  prompt field — is statically invisible to NAT-106 (known false positive).
- The execution sandbox itself (the `local_sandbox` container's network and
  filesystem posture, a Piston server's isolation) is deployment
  configuration outside the scanned repo.
- The server side of NAT's MCP story — `nat mcp serve` binding to
  `0.0.0.0` without authentication — is a runtime/CLI posture, not a config
  fact this pack reads.

---

## Recommendations beyond the fix

```yaml
function_groups:
  mcp_tools:
    _type: mcp_client
    server:
      transport: streamable-http          # NAT-105: never sse beyond a dev loop
      url: "https://mcp.internal.example/mcp"
      auth_provider: mcp_oauth2           # only honored on streamable-http
    include:                              # NAT-101: reviewed allow-list, fails closed
      - read_file
      - list_directory
    tool_call_timeout: 60

middleware:
  code_guardrails:                        # NAT-106: policy engine at the boundary
    _type: guardrails
    workflow_functions:
      - code_execution_tool
    guardrails: { ... }                   # NeMo Guardrails policy (input + output rails)

functions:
  code_execution_tool:
    _type: code_execution
    uri: "http://127.0.0.1:6000"
    timeout: 10
    middleware: ["code_guardrails"]       # attach it — declaration alone gates nothing

workflow:
  _type: react_agent
  tool_names:
    - mcp_tools
    - code_execution_tool
  max_tool_calls: 8
```

1. Treat every `include:` list as a reviewed allow-list: name only the tools
   the workflow's task needs, re-review it whenever the task changes, and
   prefer `include` over `exclude` — the server adding a tool must default to
   *excluded*.
2. Pin and verify the MCP servers themselves (exact image tags or package
   versions for stdio servers, TLS plus `auth_provider` for remote ones) —
   the filter constrains names, not what the server makes those names do.
3. Use `tool_overrides` to rewrite inherited tool descriptions in your own
   words; the model should never reason over prose the server operator can
   change under you.
4. Keep SSE configs non-promotable: if a dev loop must use `transport: sse`,
   keep the URL on localhost and treat the file as blocked from shared
   environments as it stands — NVIDIA's warning, not just ours.
5. Attach the guardrails middleware to the `code_execution` function's own
   `middleware:` list (NAT-106 cannot check attachment for you), enable input
   rails on the code string, and pair it with a HITL approval for anything
   beyond throwaway analytics.
6. Harden the executor independently of the rails: run the sandbox with no
   network egress, no mounted volumes, a tight `timeout`, and a bounded
   `max_output_characters` — the middleware bounds what is attempted, the
   sandbox bounds what an attempt can touch.
