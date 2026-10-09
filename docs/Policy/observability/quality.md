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
references: [LLM02, LLM10]
---

# Policy Rationale: Agent Observability Quality

**Policy ID:** `observability_quality`  
**File:** `observability/quality.yaml`  
**Rules:** OBS-001, OBS-002, OBS-003, OBS-005  
**Severities:** medium, low, medium, medium  
**Fix types:** code, config, config, code  
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
