---
policy_id: observability_quality
category: observability
topic: quality
rules:
  - id: OBS-001
    severity: medium
    confidence: 0.7
    scope: repo
    fix_type: code
  - id: OBS-002
    severity: low
    confidence: 0.6
    scope: repo
    fix_type: config
  - id: OBS-003
    severity: medium
    confidence: 0.8
    scope: repo
    fix_type: config
  - id: OBS-005
    severity: medium
    confidence: 0.65
    scope: repo
    fix_type: code
  - id: OBS-006
    severity: low
    confidence: 0.7
    scope: repo
    fix_type: code
  - id: OBS-007
    severity: medium
    confidence: 0.65
    scope: repo
    fix_type: code
  - id: OBS-008
    severity: medium
    confidence: 0.6
    scope: repo
    fix_type: code
references: [LLM02, LLM10]
---

# Policy Rationale: Agent Observability Quality

**Policy ID:** `observability_quality`  
**File:** `observability/quality.yaml`  
**Rules:** OBS-001, OBS-002, OBS-003, OBS-005, OBS-006, OBS-007, OBS-008  
**Severities:** medium, low, medium, medium, low, medium, medium  
**Fix types:** code, config, config, code, code, code, code  
**References:** LLM02 (Sensitive Information Disclosure), LLM10 (Unbounded Consumption)

---

## What this policy covers

These rules fire on repos where observability instrumentation is **present but
not working**, as opposed to absent. OBS-001, OBS-002 and OBS-003 read the typed
`ObservabilitySignal` records the scanner's `DiscoverObservability` pass
produces, each carrying a vendor (`otel`, `langfuse`, `logfire`,
`openinference`, `openllmetry`, `braintrust`, `weave`, `agentops`, `mlflow`,
`datadog_llmobs`, …) and a `Kind` that grades the evidence: `import` (the module
is imported), `init` (a tracer provider is set or a vendor client is
constructed), `exporter` (a span exporter is constructed, normalized to its sink
— `console`, `otlp`, `jaeger`, `zipkin`, `memory`), `content_capture` (a switch
that sends full prompt/response text to the backend), and `instrument_kwarg` (a
per-agent opt-in such as Pydantic AI's `instrument=`). OBS-001 fires when
signals exist but none is `init` or `instrument_kwarg`; OBS-002 when exporters
exist and every one has sink `console`; OBS-003 when any `content_capture`
signal is present.

OBS-006, OBS-007 and OBS-008 cover a different layer: tracing that works, but
whose spans say too little to diagnose an agent. They check for `agent-reliability-otel-labels`,
the library that adds process-metadata labels (run identity, step order,
argument and result fingerprints, attempt count, side-effect class, exit reason)
to spans the agent already emits. They read a separate set of typed records,
`OtelLabelsSignal`, produced by the scanner's `DiscoverOtelLabels` pass, with
a `Kind` of `import`, `run_start`, `tool_span` or `run_end`, plus the recon fact
`RepoProfile.OtelLabelsDeclaredIn`. These records are kept out of the
`ObservabilitySignal` set on purpose: `agent-reliability-otel-labels` never creates a span, so
counting it as observability would let the library satisfy its own prerequisite.

---

## Why observability quality is a distinct concern in agent systems

Instrumentation that is imported and never started is worse than no
instrumentation, because it is indistinguishable from working instrumentation
everywhere a human looks. The dependency manifest lists the vendor. The import
appears at the top of the module. A reviewer checking "do we have tracing?"
finds both and moves on. The spans are created and dropped, and the absence is
discovered during the first incident, which is precisely when the missing data
is most expensive.

This lands harder on agents than on conventional services. A request handler
that loses its traces still has deterministic code a developer can re-read to
reason about what happened. An agent run is non-deterministic: the model chose
those tools, in that order, with those arguments, because of a context window
that no longer exists. Reconstructing it from application logs alone is
unreliable, and re-running the input does not reproduce the failure. The trace
is not a convenience for this class of system; it is the only record of what the
agent actually did.

The content-capture rule inverts the direction of the risk. Agent prompts
routinely carry whatever the user typed, text retrieved from internal documents,
and tool outputs. Switching on message-content capture sends all of it verbatim
to a tracing backend — often a third-party SaaS, usually with long retention and
broad team-wide read access, and typically procured as an engineering tool
rather than as a data processor. The mechanism is not a vulnerability in the
tracing vendor; it is that the data classification of what flows through an agent
is much higher than what flows through a typical APM span, and the default
configuration does not know that.

---

## Rule-by-rule defense

### OBS-001 — Observability instrumentation is imported but never initialized (Severity: medium, Confidence: 0.7, Fix type: code)

**What we detect:**  
The repo has at least one `ObservabilitySignal` (`repo_has_observability: true`)
and none of them is of kind `init` or `instrument_kwarg`
(`repo_observability_initialized: false`). In practice: a module such as
`langfuse`, `opentelemetry`, `logfire`, or `braintrust` is imported, but no
`set_tracer_provider(...)`, `logfire.configure()`, `Traceloop.init()`,
`agentops.init()`, `braintrust.init_logger()`, `CallbackHandler(...)`, or
equivalent appears in any parsed file.

**Why it is flaggable:**  
An import loads the library; it does not register a provider or an exporter. In
OpenTelemetry the default global tracer provider is a no-op, so spans are
created and discarded. Vendor SDKs behave equivalently: without an initialized
client there is nothing holding a queue or a connection to flush to. The code
therefore executes the instrumentation path on every request and produces no
data anywhere.

**Real-world consequence:**  
- A team adds `langfuse` to `requirements.txt` and imports it in `app.py`
  during a spike, then never wires the handler. Six weeks later an agent starts
  looping over a tool; the on-call engineer opens the Langfuse project to find
  it empty, and the investigation restarts from stdout logs.
- A migration moves provider setup into a module that is no longer imported by
  the entrypoint. The import remains, the init no longer runs, and no test
  covers "did a span reach the backend" — so nothing fails until someone needs a
  trace.

**Why severity is medium and not low:**  
This is a state the repo is provably in, not a stylistic preference: the
instrumented path runs and produces nothing. It is medium rather than high
because it degrades diagnosis rather than causing incorrect agent behavior or
data exposure — no user-facing action changes because of it. It is medium rather
than low because it actively misleads: the repo looks instrumented to every
check short of querying the backend, which is what separates it from the plain
absence case (the per-SDK `low` rules).

**Fix type — code:**  
The remedy is adding an initialization call at process start, in application
source. It cannot be achieved through a guardrail, hook, or sandbox policy.

**Confidence 0.7:**  
The 0.30 gap is dominated by initialization the pass cannot see. False
positives: init performed in a language the Phase 1 pass does not parse (Go, C#,
PHP, Rust); init done declaratively through an environment variable or an
auto-instrumentation agent (`opentelemetry-instrument`, `OTEL_*` env config,
a sidecar) with no call site in the repo; init behind a lazily imported module
or a feature flag; init in a framework entrypoint outside the scanned tree.
False negatives: an init call that is present but unreachable, or a provider
constructed and then never registered globally — both look initialized to this
predicate.

### OBS-002 — The only span exporter writes to the console (Severity: low, Confidence: 0.6, Fix type: config)

**What we detect:**  
At least one `exporter` signal exists and every one has sink `console`
(`repo_observability_console_only: true`) — constructors such as
`ConsoleSpanExporter` / `ConsoleExporter` with no `OTLPSpanExporter`,
`OTLPTraceExporter`, `JaegerExporter`, or `ZipkinExporter` anywhere in the
parsed source. A repo with no exporters at all does not fire this rule; that is
the absence case.

**Why it is flaggable:**  
A console exporter writes span text to the process's stdout. It satisfies "is
tracing configured?" while producing no queryable history: nobody can search
last week's runs, compare a regression against a baseline, or alert on an error
rate, because no store received the spans. On a stdio-transport MCP server the
consequence is sharper — stdout is the JSON-RPC protocol channel, so span text
interleaves with protocol frames and can corrupt the stream.

**Real-world consequence:**  
- A service ships with the console exporter from the getting-started guide. In
  production the spans land in the container's stdout, get truncated by the log
  driver, and are unusable for correlating an agent failure across a run.
- An MCP server built for local testing keeps its console exporter when it moves
  to stdio transport; clients begin seeing malformed responses under load.

**Why severity is low and not medium:**  
Unlike OBS-001, the flagged configuration is legitimately correct in context. A
development script, an example, a CLI tool, or a local test harness exports to
the console on purpose, and this rule cannot distinguish those from a production
service. Firing at medium would fail CI (exit 1) on every such repo. The
evidence supports "look at this", not "this is broken".

**Fix type — config:**  
Adding or switching an exporter is provider wiring, typically environment-driven
(`OTEL_EXPORTER_OTLP_ENDPOINT`) and selected by an environment check. No agent or
tool logic changes.

**Confidence 0.6:**  
The 0.40 gap reflects the intent ambiguity above. False positives: development
and example code where console is the correct sink; a console exporter guarded
by an `if DEBUG` branch the predicate does not evaluate; an OTLP exporter
configured purely through environment variables with no constructor in source.
False negatives: a network exporter constructed through a factory or a wrapper
whose name is not in the exporter table, which makes the repo look console-only
when it is not — and, conversely, an exporter pointed at a collector that is not
running, which this rule cannot detect at all. The rule ships `language: python`
even though `applies_to` lists TS-heavy SDKs (`vercel_ai`, and the TS variants of
`claude_sdk` / `langchain` / `google_adk` / `mcp`): the exporter-construction walk
has no TS/JS counterpart yet, so `language: python` is what keeps the rule from
advertising coverage on repos it cannot actually inspect, rather than silently
never firing there. Closing the gap is TS/JS exporter-construction detection, not
scoped for Phase 1.

### OBS-003 — Tracing captures full prompt and response content (Severity: medium, Confidence: 0.8, Fix type: config)

**What we detect:**  
A `content_capture` signal (`repo_observability_captures_content: true`): a
truthy `include_content`, `capture_content`, `log_prompts`, or `log_completions`
kwarg, or a string literal naming a content-capture environment variable such as
`OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT`, `TRACELOOP_TRACE_CONTENT`,
`LANGFUSE_CAPTURE_INPUT`, or `LANGFUSE_CAPTURE_OUTPUT`.

**Why it is flaggable:**  
With content capture on, the full text of every prompt and completion is
attached to spans and exported. For an agent, that text is not a sanitized API
payload: it includes the user's raw input, retrieved document content, tool
results, and any system-prompt material carried in the request. The tracing
backend then holds a copy under its own retention and access rules, which were
chosen for telemetry rather than for the data classification of the content now
flowing into it.

**Real-world consequence:**  
- A support agent retrieves customer records to answer a question. With content
  capture on, those records are written into trace storage at a third-party
  vendor, where the whole engineering org can read them and retention is 30–90
  days by default.
- A user pastes an API key into a chat to ask why it is failing. The key is now
  in the prompt body, in the trace, in whatever backup that vendor keeps, and
  outside the scope of the credential-rotation process that would otherwise
  apply.

**Why severity is medium and not high:**  
The mechanism is real and the data is genuinely sensitive, but the impact is
conditional on facts this rule cannot see: whether the backend is self-hosted or
third-party, whether the agent actually handles regulated data, and whether a
redaction processor sits in front of the exporter. High would assert an exposure
this rule has not established. It is not low because the default path — hosted
vendor, no redaction — is the common one, and the data is exactly the kind an
organization cannot un-disclose.

**Fix type — config:**  
Content capture is a flag or an environment variable, and redaction is a span
processor registered at provider setup. Neither requires changing tool or agent
logic.

**Confidence 0.8:**  
The 0.20 gap is about consequence, not detection: the switch itself is matched
from a typed AST node, so the pattern is reliable. False positives: capture
enabled deliberately in a local or staging configuration; capture paired with a
redaction processor the rule does not model, which makes the finding technically
true but practically mitigated; an agent that only ever handles synthetic data.
False negatives: a vendor SDK whose capture default is *on* with no explicit
switch in source — the commonest real exposure, and one this rule cannot see
precisely because there is nothing written down to detect. Like OBS-002, this
rule ships `language: python` even though `applies_to` lists TS-heavy SDKs: the
content-capture walk (kwargs and env-var literals) has no TS/JS counterpart yet
— Vercel's `experimental_telemetry: { recordInputs: true }` is not detected —
so `language: python` keeps the rule honest about what it can actually inspect.

---

### OBS-005 — An observability dependency is declared but never wired (Severity: medium, Confidence: 0.65, Fix type: code)

**What we detect:**  
An observability package is declared in a hand-edited dependency manifest
(`repo_observability_declared: true`, read from `RepoProfile.ObsDeps`), the repo
has no observability signal in code at all (`repo_has_observability: false`), and
the repo contains at least one language the pass parses
(`repo_observability_inspectable: true`). This is the only rule in the catalog
whose evidence comes from recon rather than the AST inventory. The predicate
counts `pyproject.toml`, `requirements.txt`, `Pipfile` and `package.json` only —
`poetry.lock` is deliberately excluded.

**Why it is flaggable:**  
Adding a package to a manifest is a deliberate act with a cost: it is installed,
it ships in the image, it appears in the SBOM, and it is scanned for
vulnerabilities. When nothing imports it, that cost buys nothing and the
artifacts it produces actively assert a capability the running system does not
have. Unlike OBS-001, where instrumentation code at least executes, here not a
single line runs — the dependency is inert.

**Real-world consequence:**  
- A platform team standardizes on Langfuse and adds it to every service's
  `requirements.txt` as part of a rollout. Three services never complete the
  wiring. The rollout is reported as done because the dependency is present
  everywhere, and the gap surfaces during an incident in one of the three.
- A security review reads the SBOM, sees an observability vendor, and records
  the service as covered by tracing for an audit question about agent
  monitoring. No trace has ever been emitted.
- An instrumentation module is deleted during a refactor while the manifest
  entry survives — nothing fails, because an unused dependency breaks nothing.

**Why severity is medium and not low:**  
It sits at medium for the same reason as OBS-001, and the team framing that
motivated the rule states it directly: a repo that never adopted observability
has made a choice a reviewer can see, and the nine absence rules warn about it
at `low`. A repo that ships the dependency has made the opposite choice on
paper and failed to carry it out, so every downstream artifact — manifest,
lockfile, SBOM, image — misrepresents the system's actual observability. Being
wrong about coverage is worse than knowingly having none. It is not high
because, as with OBS-001, nothing about the agent's behavior or data handling
changes; only the ability to diagnose it does.

**Fix type — code:**  
The intended remedy is to wire the dependency that is already shipped: import it
and initialize it at process start. Removing the manifest entry is the honest
alternative when the adoption was abandoned, but the rule's fix text leads with
the code path because a declared dependency usually reflects an intent worth
completing.

**Confidence 0.65 — below OBS-001's 0.7:**  
The evidence is one manifest line, which is weaker than an import statement. The
0.35 gap:
- **`pip freeze`-style manifests.** A `requirements.txt` generated by
  `pip freeze` enumerates the transitive closure, so `opentelemetry-sdk` can
  appear there without anyone choosing it. The predicate cannot distinguish a
  frozen manifest from a curated one. This is the single largest false-positive
  source, and the reason the rule is not higher than medium.
- **Instrumentation without a call site.** Auto-instrumentation
  (`opentelemetry-instrument`, `OTEL_*` environment configuration, a Datadog or
  OTel sidecar, a platform agent injected at deploy) works precisely by
  declaring the dependency and writing no code. Such a repo is correctly
  instrumented and will still fire.
- **Unparsed languages.** The inspectability gate stops a Go-only repo firing,
  but a mixed repo whose instrumentation lives in its Go service and whose
  manifest sits at the root will fire on the Python half.
- **Test-only or tooling dependencies.** `mlflow` or `weave` declared for
  experiment tracking in notebooks, not for agent tracing.
- **False negatives**, by construction: a dependency declared only in
  `poetry.lock`, `package-lock.json`, or a container image is not seen at all.
  That is the intended trade — a lock file carries the transitive closure, where
  a match proves nobody's intent, and blaming a repo for its framework's
  dependencies would be worse than missing the case.

**Relationship to the other observability rules:**  
The three states are mutually exclusive by construction, and exactly one fires:

| Repo state | Rule | Severity |
|---|---|---|
| No dependency, no code | the nine per-SDK absence rules | low |
| Dependency declared, no code | **OBS-005** | medium |
| Imported in code, never initialized | OBS-001 | medium |

The nine absence rules carry `repo_observability_declared: false` for exactly
this reason: without it, a declared-but-unwired repo would draw the `low`
"wires no observability" finding, which understates it.

---

### OBS-006 — Instrumented agent does not label its spans with agent-reliability-otel-labels (Severity: low, Confidence: 0.7, Fix type: code)

**What we detect:**  
Instrumentation is switched on (`repo_observability_initialized: true` — an init
call or a per-agent instrument kwarg) and `agent-reliability-otel-labels` is absent
(`repo_otel_labels_installed: false`). "Absent" means both halves are missing:
no root manifest declares it (`agent-reliability-otel-labels` or `agent_reliability_otel_labels` in
`pyproject.toml`, `requirements.txt`, `Pipfile` or `poetry.lock`;
`@trustabl/agent-reliability-otel-labels` in `package.json`), and no parsed Python or
TypeScript/JavaScript file imports `agent_reliability_otel_labels` or `@trustabl/agent-reliability-otel-labels`. Either
half alone silences the rule.

**Why it is flaggable:**  
A span produced by an agent framework's instrumentation records that a tool ran,
when, and for how long. It does not record whether this call had the same
arguments as an earlier one, whether it was a retry, whether it changed outside
state, or how the run ended. Those are the facts that separate a healthy run
from a looping, retrying or truncated one, and none of them can be recovered
from the span afterwards: argument text is usually not captured (and should not
be — see OBS-003), so two calls cannot be compared, and a framework does not
report that it stopped at a step cap as distinct from finishing. The gap is in
what the spans carry, not in whether they are exported.

**Real-world consequence:**  
- An agent calls the same search tool with the same arguments twelve times
  before giving up. Each span is a short, successful tool call. The trace looks
  busy, not broken, and the loop is found only when someone reads the spans in
  order by hand.
- A run stops at its step limit on every invocation and returns whatever it had.
  From the outside the run completed without error, so the truncation is
  invisible in dashboards and surfaces as a quality complaint.
- A tool that sends a payment is retried after a timeout. Without an attempt
  count and a side-effect class on the span, the trace cannot show that an
  irreversible call ran twice.

**Why severity is low and not medium:**  
Nothing is misrepresented. The repo has working tracing and makes no claim to
have process labels, which is the same position as a repo with no tracing at
all, and the nine per-SDK absence rules sit at `low` for that reason. This rule
also recommends a specific library, published by the authors of the scanner, as
the remedy. That is a recommendation about depth of diagnosis, not a defect in
the agent, and it should not outrank findings that are. The same labels can be
written by hand; the rule names the library because it is the implementation
the scanner can recognize.

**Fix type — code:**  
Installing the package changes nothing on its own. The remedy is the labelling
code: a `Run` per agent run, `mark_start` on the root span, `mark_tool_span` on
each tool span and `mark_run_end` before the root span closes.

**Confidence 0.7:**  
The 0.3 gap:
- **Instrumentation that does not emit OpenTelemetry spans.** The gate is "any
  instrumentation is initialized", across every vendor the observability pass
  knows. `agent-reliability-otel-labels` labels OpenTelemetry spans. A repo whose only tracing
  is a vendor's own non-OpenTelemetry client, or a LangChain `callbacks=` list
  holding an arbitrary handler, will fire although the library has no span to
  label there. This is the largest false-positive source.
- **The Go binding.** Only Python and TypeScript/JavaScript are inspected, and
  `go.mod` is not read. A mixed repo that labels its spans in a Go service and
  initializes tracing in a Python one will fire.
- **Nested manifests.** Recon reads root manifests only. A monorepo that
  declares the library in `services/agent/pyproject.toml` is credited only
  through its import, so a package that is declared there and not yet imported
  draws this rule instead of OBS-007.
- **Hand-written labels.** A repo that sets the `trustabl.*` attribute keys
  directly with `span.set_attribute` has the labels and will still fire.

---

### OBS-007 — agent-reliability-otel-labels is installed but no run is ever started (Severity: medium, Confidence: 0.65, Fix type: code)

**What we detect:**  
Instrumentation is switched on (`repo_observability_initialized: true`),
`agent-reliability-otel-labels` is present (`repo_otel_labels_installed: true`), and no run is
started (`repo_otel_labels_initialized: false`). A run is started by a call to
`mark_start` on a `Run` — `<run>.mark_start(...)` in Python,
`<run>.markStart(...)` in TypeScript/JavaScript. The call must have a receiver:
a bare `mark_start(...)` is some other function. Constructing a `Run` does not
count, and neither do `mark_tool_span` or `mark_run_end` calls on their own.

**Why it is flaggable:**  
`mark_start` is the call that writes `trustabl.run_id` on the root span. Every
other label is interpreted relative to a run: step order is an order within a
run, an attempt count is a count within a run, and a repeated fingerprint means
a loop only when both calls belong to the same run. With no run identity on the
root span, tool-span labels cannot be grouped and the labels that were written
cannot be read as intended. The library is present and partly used, and the one
call that makes the rest meaningful is missing.

**Real-world consequence:**  
- A team adds the dependency and the imports during a tracing rollout and never
  reaches the root-span wiring. The package ships in the image and the SBOM, and
  no trace carries a run id.
- Tool spans are labelled with fingerprints and attempt counts inside a tool
  wrapper, but the agent entrypoint never calls `mark_start`. A query for
  repeated fingerprints returns matches across unrelated runs, and what looks
  like a loop is two users asking the same question.

**Why severity is medium and not low:**  
The reasoning is OBS-005's: a repo that has not adopted the library has made a
visible choice and draws OBS-006 at `low`; a repo that ships it has made the
opposite choice on paper and not carried it out. The manifest and the imports
assert a capability that an exported trace does not have. It is not high because
the agent's behavior and data handling are unchanged; only the ability to
diagnose it is.

**Fix type — code:**  
One `Run` per agent run, constructed inside the function that runs the agent,
and `run.mark_start(root)` on the root span as soon as it is open.

**Confidence 0.65:**  
The 0.35 gap:
- **A run started through a wrapper.** A project helper that receives the `Run`
  and calls `mark_start` is seen. One that hides the call behind `getattr`, or
  imports it under an alias the call-name match does not follow, is not.
- **Lock-file-only declarations.** `poetry.lock` counts as installed here,
  unlike OBS-005, because nothing depends on `agent-reliability-otel-labels` transitively. A
  lock file left over after the dependency was removed from `pyproject.toml`
  will fire.
- **A run started in Go.** As in OBS-006, a Go service that calls
  `run.MarkStart` is not inspected.
- **Repo-wide name matching.** Once any file imports the library, a
  `.mark_start(` call on an unrelated object anywhere in the repo is credited as
  a run start. That is a false negative, accepted so that a `Run` built in one
  module and started in another is recognized.

---

### OBS-008 — An agent-reliability-otel-labels run is started but its spans are never labelled (Severity: medium, Confidence: 0.6, Fix type: code)

**What we detect:**  
Instrumentation is switched on (`repo_observability_initialized: true`), a run
is started (`repo_otel_labels_initialized: true`), and the labels are not
written (`repo_otel_labels_implemented: false`). "Written" requires a
`mark_run_end` / `markRunEnd` call, and, when the repo ships at least one tool
the model calls, a `mark_tool_span` / `markToolSpan` call as well. The tool
obligation is read from the typed inventory: a tool counts when its kind is one
an agent framework emits a tool-execution span for. A bare shell-invoking
function and a LangGraph node do not count, and a repo with no such tool needs
only the run end.

**Why it is flaggable:**  
A started run with no labels is a root span carrying a run id and nothing else.
The run id groups spans; it answers none of the questions the library exists to
answer. Without `mark_tool_span` there are no input or output fingerprints, no
attempt count, no side-effect class and no step index. Without `mark_run_end`
there is no exit reason, so a run stopped by its step cap or by a policy reads
the same as one that returned a final answer.

**Real-world consequence:**  
- The root-span wiring lands in one change and the per-tool labelling is left
  for a follow-up that does not happen. Dashboards show run ids on every trace,
  which reads as done.
- A new tool is added to an agent whose other tools are labelled through a
  shared wrapper the new tool does not use. This rule does not catch that case
  (see the gap below), but it is the same failure at smaller scale.
- `mark_run_end` is omitted, and a weekly review of "runs that ended in
  `max_steps`" returns nothing because no run records an exit reason at all.

**Why severity is medium and not low:**  
The same argument as OBS-007, one rung further along: the repo asserts more
(dependency, imports, a started run) and delivers less than it appears to. It is
not high for the same reason as the other rungs.

**Fix type — code:**  
`mark_tool_span` on each tool's span, inside a `finally` block so that a failing
call is still labelled, and `mark_run_end` before the root span ends, with
`error` on the exception path.

**Confidence 0.6 — the lowest of the three:**  
The rule proves that calls exist, which is weaker evidence in both directions.
The 0.4 gap:
- **Partial labelling passes.** One `mark_tool_span` call anywhere satisfies the
  tool obligation for a repo with twenty tools. The rule is a repo-level floor,
  not a per-tool check, because labelling in a shared wrapper or hook is a
  legitimate pattern the scanner cannot tie back to individual tools.
- **Tools the agent does not use.** The obligation is triggered by any
  discovered tool in the repo. A repo whose instrumented agent is tool-less but
  which also contains an unrelated MCP server will fire for the missing
  `mark_tool_span`.
- **Externally defined tools.** An agent whose tools all come from a remote MCP
  server or a hosted tool has no discovered tool definition, so the rule accepts
  the run end alone although tool spans exist at run time.
- **Run end on one path only.** A `mark_run_end` call that is reached only on
  success satisfies the rule and leaves failed runs without an exit reason.

**Relationship between the three agent-reliability-otel-labels rules:**  
All three are gated on `repo_observability_initialized: true`, because the
library only labels spans that already exist; a repo with no tracing draws its
SDK's absence rule instead and none of these. Within that gate the states are
mutually exclusive, and at most one rule fires:

| Repo state | Rule | Severity |
|---|---|---|
| Not declared, not imported | OBS-006 | low |
| Declared or imported, no `mark_start` | OBS-007 | medium |
| `mark_start` present, labels missing | OBS-008 | medium |
| `mark_start`, `mark_run_end` and (if tools exist) `mark_tool_span` | none | — |

## What this policy does not cover

- **Initialization outside the parsed languages.** Phase 1 parses Python and
  TypeScript/JavaScript only. A Go, C#, PHP, or Rust repo produces no
  observability signals at all, so none of these rules fire there — the absence
  rules guard against misreading that with `repo_observability_inspectable`, but
  these quality rules simply stay silent.
- **Declarative and agent-based instrumentation.** Auto-instrumentation via
  `opentelemetry-instrument`, `OTEL_*` environment configuration, a collector
  sidecar, or a platform-injected agent leaves no call site, so OBS-001 will
  report an uninitialized repo that is in fact fully instrumented.
- **Whether traces reach anything.** An OTLP exporter pointed at a collector
  that is down, misconfigured, or dropping data satisfies every rule here. These
  are static checks on wiring, not liveness checks.
- **Sampling.** A correctly initialized provider with a 0% sampler produces no
  usable traces and passes all three rules.
- **Span quality.** Nothing here checks whether spans follow the OTel GenAI
  semantic conventions, carry token/cost attributes, or record errors with a
  status — the last of which is deliberately deferred to the runtime phase,
  where trace data can answer it instead of static analysis guessing.
- **Vendor default behavior.** OBS-003 detects an explicit switch. A vendor
  whose default is to capture content is invisible to it.
- **Redaction that is present.** A span processor that strips message bodies
  before export does not silence OBS-003; the finding is then accurate about the
  switch but overstated about the exposure.
- **Whether agent-reliability-otel-labels labels land.** Every label call is a silent no-op when
  there is no current span inside the tool, for example because no context
  manager is registered. A repo in that state passes OBS-006, OBS-007 and
  OBS-008 and writes no label. Only exporting one run and looking for
  `trustabl.tool.input_fp` on a tool span shows it.
- **Whether agent-reliability-otel-labels is used correctly.** A `Run` shared between runs, a
  constant `attempt`, labelling outside a `finally` block, a `side_effect` value
  that contradicts what the tool does, and a missing `mark_handoff` on a
  delegated agent all pass. These are deferred static checks.
- **Label values.** Whether `write` should have been `irreversible`, or `error`
  should have been `max_steps`, is not something a static check can decide.

---

## Recommendations beyond the fix

```python
# tracing.py — imported by the application entrypoint before any agent runs.
import os

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

REDACT_KEYS = {"gen_ai.prompt", "gen_ai.completion", "input.value", "output.value"}


class RedactingSpanProcessor(BatchSpanProcessor):
    """Drops message bodies before they leave the process (OBS-003)."""

    def on_end(self, span):
        if span.attributes:
            for key in REDACT_KEYS & set(span.attributes):
                span._attributes[key] = "[redacted]"
        super().on_end(span)


def configure_tracing() -> None:
    provider = TracerProvider(resource=Resource.create({"service.name": "support-agent"}))

    # OBS-002: a network exporter is the production sink. The console exporter
    # is opt-in for local work, never the only sink.
    provider.add_span_processor(
        RedactingSpanProcessor(OTLPSpanExporter(endpoint=os.environ["OTEL_EXPORTER_OTLP_ENDPOINT"]))
    )
    if os.getenv("TRACE_TO_CONSOLE") == "1":
        provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))

    # OBS-001: this call is what makes every span above reachable. Without it the
    # global provider stays a no-op and everything here is dead code.
    trace.set_tracer_provider(provider)
```

1. **Assert a span reaches the backend in CI.** Run one agent invocation against
   an in-memory exporter and fail the build if the span count is zero. This is
   the only check that catches an init that stops running after a refactor —
   the failure mode OBS-001 exists to describe.
2. **Keep content capture off by default and opt in per environment.** Make the
   production value the default and the permissive value the exception, so a
   missing environment variable fails closed.
3. **Set the service resource attributes** (`service.name`, `service.version`,
   `deployment.environment`) at provider construction. Without them, traces from
   several agents land in one undifferentiated stream and per-agent attribution
   is lost.
4. **Decide retention deliberately for agent traces.** If content capture is on
   anywhere, shorten retention and restrict project access to match the
   sensitivity of prompt bodies rather than accepting the vendor's telemetry
   default.
5. **Record the trace ID on user-facing errors.** Without a correlation handle,
   a user report cannot be matched to the run that produced it, and the trace —
   however well configured — goes unread.
