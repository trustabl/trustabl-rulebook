---
policy_id: mcp_tracing
category: mcp
topic: tracing
rules:
  - id: MCP-202
    severity: low
    confidence: 0.75
    scope: repo
    fix_type: config
references: [LLM10]
---
# Policy Rationale: MCP Server Observability Configuration

**Policy ID:** `mcp_tracing`  
**File:** `mcp/tracing.yaml`  
**Rules:** MCP-202  
**Severities:** low  
**Fix types:** config  
**References:** LLM10 (Unbounded Consumption)

---

## What this policy covers

A repo-scoped check: the project implements an MCP server in code, no
observability signal was found, and the repo contains a language the
observability pass parses.

---

## Why observability is a distinct concern in MCP Server projects

An MCP server is driven by a client it does not control and usually
cannot see. Its failures do not surface in its own product — they surface to
someone in a different application, as an unexplained tool error, often described
only as "the assistant said it couldn't do it".

That reporting asymmetry is what makes server-side traces load-bearing here.
Without them there is nothing to correlate a user's vague report against: no
record of which tool was called, with which arguments, by which client, or
whether it failed on validation, on a timeout, or on an upstream error.

---

## Rule-by-rule defense

### MCP-202 — MCP server wires no observability (Severity: low, Confidence: 0.75, Fix type: config)

**What we detect:**  
MCP code is present (`repo_has_sdk_in_code: [mcp]`), no observability
signal of any kind was found, and the repo is inspectable. No observability package is declared in a hand-edited dependency manifest
either (`repo_observability_declared: false`): a repo that ships a tracing
dependency it never wired draws OBS-005 at medium instead, since it has
claimed coverage it does not have. Note the language
gate: the pass reads Python and TypeScript/JavaScript, so Go, C#, PHP and Rust
MCP servers are not inspected and the rule stays silent for them.

**Why it is flaggable:**  
The server sees every tool invocation the agent makes, which makes it the
best-placed component to record them — and the only one with access to the
arguments and the error. A server with no instrumentation discards the only
first-hand record of the interaction.

**Real-world consequence:**  
- A tool starts failing on inputs containing a particular character. Users
  report the assistant "not working sometimes"; with no server traces there is no
  way to find the common factor.
- A client begins calling one tool in a tight loop. The server absorbs the load
  and the upstream API rate-limits, with nothing identifying the calling client.

**Why severity is low and not medium:**  
Missing observability degrades diagnosis; it does not itself cause incorrect
behavior or expose data. Examples, tutorials, internal libraries, and prototypes
legitimately ship without it, and at medium this rule would exit 1 and fail CI on
every one of them. Low keeps the gap visible and scored without turning "no
tracing" into a build break. Contrast OBS-001, which is medium because it
describes instrumentation that is present and provably broken.

**Fix type — config:**  
Provider initialization at server start. No tool handlers change.

**Confidence 0.75:**  
The 0.25 gap is detection reach, not judgement. False positives: instrumentation
configured entirely through environment variables or an auto-instrumentation
agent with no call site in the repo; a provider initialized in a deployment
wrapper outside the scanned tree; a vendor SDK absent from the detection table.
False negatives are structurally excluded — the rule fires only when *zero*
signals were found, and the `repo_observability_inspectable` gate suppresses it
in languages the pass does not read, so "we did not look" is never reported as
"you have none".

---

## What this policy does not cover

- **Declarative instrumentation.** `opentelemetry-instrument`, `OTEL_*`
  environment configuration, a collector sidecar, or a platform-injected agent
  leaves no call site, so a fully instrumented deployment can still fire the
  absence rule.
- **Languages the pass does not parse.** Phase 1 reads Python and
  TypeScript/JavaScript. The `repo_observability_inspectable` gate keeps the
  rule silent elsewhere rather than guessing from an empty result.
- **Whether the wiring works.** Any signal at all silences the absence rule,
  even if the instrumentation is never initialized (OBS-001), exports only to
  the console (OBS-002), or samples at zero.
- **Trace quality.** Nothing here checks GenAI semantic-convention compliance,
  token/cost attributes, or error status recording.

---

## Recommendations beyond the fix

```python
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from mcp.server.fastmcp import FastMCP

provider = TracerProvider()
# Network exporter, never a console one: on stdio transport, stdout IS the
# JSON-RPC channel and loose writes corrupt the protocol stream.
provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
trace.set_tracer_provider(provider)

mcp = FastMCP("files")
```

1. **Never log or export to stdout on a stdio-transport server.** Use stderr or a
   network exporter; stdout belongs to the protocol.
2. **Record the tool name and the outcome on every span**, so a failing tool is
   identifiable without reading argument contents.
3. **Carry a client identifier** where the transport provides one, so a
   misbehaving client is attributable.
