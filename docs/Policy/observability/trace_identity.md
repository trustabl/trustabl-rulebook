---
policy_id: observability_trace_identity
category: observability
topic: trace_identity
rules:
  - id: OBS-015
    severity: medium
    confidence: 0.45
    scope: repo
    fix_type: code
  - id: OBS-016
    severity: medium
    confidence: 0.4
    scope: repo
    fix_type: code
references: []
---

# Policy Rationale: Trace Identity and Served-Model Records

**Policy ID:** `observability_trace_identity`  
**File:** `observability/trace_identity.yaml`  
**Rules:** OBS-015, OBS-016  
**Severities:** medium  
**Fix types:** code  
**References:** none

> **Verification status.** The four papers cited below were read on 2026-11-26 as abstracts
> through the arXiv API (`export.arxiv.org`), not as full texts. The attribute names
> `gen_ai.response.model`, `gen_ai.conversation.id` and `gen_ai.tool.call.id` were read on
> 2026-11-26 in the OpenTelemetry semantic-conventions attribute registry
> (`docs/registry/attributes/gen-ai.md`), where each is marked deprecated with a note that the
> GenAI conventions moved to the `semantic-conventions-genai` repository; the names were not
> re-checked there. `trustabl.run_id` is defined in `spec/keys.json` of
> agent-reliability-otel-labels. **Not verified, and therefore not assumed:** which
> instrumentation libraries write these attributes; whether any provider repoints a name that
> ends in `-latest`; and the runtime check of OBS-015, whether a served model changed. No
> attribute name for an approval identifier is defined by either source, so OBS-016 does not
> check one.

---

## What this policy covers

Two repo-scope rules for hand-written OpenTelemetry tracing. Both fire when OpenTelemetry is
the repo's sole tracing setup: the rules stay silent if the scan sees OpenInference, OpenLLMetry,
Langfuse, LangSmith, Logfire, Braintrust, Weave, AgentOps, MLflow, Datadog LLM Observability,
Opik, LangWatch or the OpenAI default tracing, because those libraries can write some of these
attributes and the scan cannot see which. A span attribute counts as written when non-test code
calls `set_attribute`, `set_attributes`, `setAttribute` or `setAttributes` with it, or, for
`trustabl.run_id`, starts an agent-reliability-otel-labels run.

---

## Rule-by-rule defense

### OBS-015 - A judge or guardrail model call uses a floating alias and the trace does not record the served model (Severity: medium, Confidence: 0.45, Fix type: code)

**What we detect:** a function whose name contains judge, guardrail, moderat, monitor, grader or
critic, outside a test path, that sets a model name as a string literal ending in `-latest`
(`model=` argument, `model` property, or the first argument of `init_chat_model`), in a repo
where no non-test code writes `gen_ai.response.model` to a span. Gated by
`repo_judge_model_floating_alias` and `repo_otel_span_attrs_missing`.

**Why it is flaggable.** *Evaluate the Stack, Not the Layer* (arXiv 2610.07359, submitted 5
October 2026) stacks a rule layer and four LLM judges, says three of the judges were
"re-collected with the served model recorded" on each call, and reports that "one judge tier
was served by an unrequested model version in 50 of 112 batches". A judge whose served model is
not in the trace cannot show such a change. *Where Rules End and Judges Begin* (arXiv
2610.07657, submitted 6 October 2026) describes multi-agent defenses in which a panel of judges
decides what the deterministic checks refer on, which is the role the function names look for.
Both are cited for those statements and nothing more. Whether a `-latest` name was repointed in
a given repo is not known to the scan.

**Why severity is medium:** The pack sets medium and states no reasoning for it.

**Fix type - code:** pin the judge to a dated or versioned name and write the model the response
reports to the span as `gen_ai.response.model`.

**Confidence 0.45:** the explanation states these limits: a static check alone; a model that
comes from configuration, or a judge with another function name, is not seen; a `-latest`
suffix alone counts as floating, and a bare name such as `gpt-4o` is not judged; a repo that records
the served model through an instrumentation library, or by a means other than a span attribute
write, is a false positive; a write anywhere in non-test code clears the finding, even on
another span.

### OBS-016 - Tool-call spans record no run, conversation or tool-call identifier (Severity: medium, Confidence: 0.4, Fix type: code)

**What we detect:** a repo with OpenTelemetry initialized and a tool whose body shows a shell
call, a code-execution call or a file write, where no non-test code writes
`gen_ai.conversation.id`, `gen_ai.tool.call.id` or `trustabl.run_id` to a span and no
agent-reliability-otel-labels run is started. Gated by `repo_has_consequential_tool` and
`repo_otel_span_attrs_missing`.

**Why it is flaggable.** *Formal Runtime Verification for Tool-Using LLM Agents* (arXiv
2610.09793, submitted 7 October 2026) reports in its abstract that the corpora it replays
seldom record approvals and record no timestamps, so that history-dependent obligations
"reduce to detecting risky action types", and proposes a twelve-field trace schema. *Correct
Answers, Unsupported Findings* (arXiv 2610.09581, submitted 7 October 2026) reports that "a
citation identifier does not establish a source unless its binding to a record is preserved".
They are cited for those statements and nothing more; neither studies OpenTelemetry attributes.
That an identifier is needed to tie a span to a run is the pack's reading of them.

The planning sheet also named an approval identifier. Neither OpenTelemetry nor the labels spec
defines an attribute name for one, so the pack does not check it and the loader rejects an
unknown name.

**Why severity is medium:** The pack sets medium and states no reasoning for it.

**Fix type - code:** write `gen_ai.tool.call.id` and `gen_ai.conversation.id` on tool-call spans,
or start an agent-reliability-otel-labels run so the root span carries `trustabl.run_id`.

**Confidence 0.4:** the explanation states these limits: the check looks for a literal attribute
write anywhere in non-test code, not on a tool-call span; a consequential tool is one registered with an agent framework with a
shell, code-execution or file-write call in the parsed source (a bare function that calls a shell, and a tool under a test path, are not counted); identifiers carried by a library,
a framework, context or baggage, or under another name, are false positives.

---

## What this policy does not cover

- Whether a served model changed at run time (the runtime check of OBS-015).
- Approval identifiers.
- Model names set from configuration, and bare family names such as `gpt-4o`.
- Tracing set up with a named vendor besides OpenTelemetry.
- Tools that send requests or change a database.

---

## Recommendations beyond the fix

1. Record requested and served model names as separate attributes.
2. Write the tool-call id the model returned on the tool span.
3. Use one conversation or run identifier for each span of a run.

---

## Sources

- Evaluate the Stack, Not the Layer, arXiv 2610.07359; Where Rules End and Judges Begin, arXiv
  2610.07657; abstracts retrieved 2026-11-26. Cited for OBS-015 as stated above.
- Formal Runtime Verification for Tool-Using LLM Agents, arXiv 2610.09793; Correct Answers,
  Unsupported Findings, arXiv 2610.09581; abstracts retrieved 2026-11-26. Cited for OBS-016 as
  stated above.
- OpenTelemetry semantic conventions, attribute registry `docs/registry/attributes/gen-ai.md`,
  retrieved 2026-11-26. Cited for the attribute names and nothing more.
- agent-reliability-otel-labels, `spec/keys.json`, read 2026-11-26. Cited for `trustabl.run_id`.
