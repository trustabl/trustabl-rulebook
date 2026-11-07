---
policy_id: observability_reasoning
category: observability
topic: reasoning
rules:
  - id: OBS-013
    severity: medium
    confidence: 0.6
    scope: repo
    fix_type: code
  - id: OBS-014
    severity: low
    confidence: 0.6
    scope: repo
    fix_type: code
references: [LLM02, LLM07]
---

# Policy Rationale: Agent Reasoning Labels

**Policy ID:** `observability_reasoning`  
**File:** `observability/reasoning.yaml`  
**Rules:** OBS-013, OBS-014  
**Severities:** medium, low  
**Fix types:** code, code  
**References:** OWASP LLM Top 10:2025: LLM02 (Sensitive Information Disclosure), LLM07 (System Prompt Leakage)

---

## What this policy covers

These rules cover the `trustabl.cot.*` reasoning labels of
`agent-reliability-otel-labels`: `trustabl.cot.present`, `trustabl.cot.text_fp`
and `trustabl.cot.mode`, written on a model-call span by `mark_reasoning`
(Python) or `markReasoning` (TypeScript). The token count is deliberately not one
of them: it stays OTel's `gen_ai.usage.reasoning.output_tokens`.

OBS-013 fires when one of those keys is written by hand with `set_attribute` /
`setAttribute` (or the plural forms) and a value that could be the reasoning
itself. OBS-014 fires when a repo that labels its runs sets a model option that
turns reasoning on, and nothing labels a model span. Both read the same typed
`OtelLabelsSignal` records as OBS-006..012 in
[quality.md](quality.md), with three additions: the `reasoning` kind (a
`mark_reasoning` call), the `reasoning_config` kind (a model option), and
`ValueUnhashed` on a hand-written `trustabl.cot.*` key. Test files never decide
OBS-013, or the option and the label OBS-014 compares. Findings carry the file and
line of the offending write or option.

The rules are cross-SDK for the reason `quality.yaml` gives: the failure and its
fix are about the label library, identical whichever SDK declared the agent, so
`applies_to` lists every SDK token rather than shipping nine byte-identical
copies.

---

## Why reasoning labels are a distinct concern in agent systems

A chain of thought is the most sensitive text in an agent run, and the least
filtered. It quotes whatever the model read: what the user typed, retrieved
documents, tool results, and often the system prompt. Unlike a tool's arguments
it has no schema, so nothing bounds what lands in it. A team that has decided, on
good grounds, not to capture prompts in its traces (OBS-003) can still send all
of that to the same backend through one attribute, because a reasoning attribute
does not look like message content to anything configured to look for message
content.

The labels exist so a run can leave evidence of its reasoning without carrying
it. The default is a fingerprint: SHA-256 over the text's RFC 8785 form, first 16
hex characters, the same form the library uses for tool arguments. That hash lets
a text captured elsewhere under an explicit opt-in be matched to the span that
saw it, and it tells a reader whether two calls produced the same reasoning. No
OTel convention for hashing reasoning was found, so this default is Trustabl's
own design, and rollout needs a privacy and compliance review. The hash is one-way
but not secret: anyone already holding a candidate text can hash it and confirm
the match.

The failure path for a hand-written key is quiet. `trustabl.cot.text_fp` reads as
content-free to every consumer, so a span where someone passed the text instead
of its hash looks correctly labelled, and neither a content filter nor a reviewer
has a reason to open it. The failure path for a missing label is quieter still:
the tool calls are labelled, the trace looks complete, and the question "what
did the model reason before this call" has no answer when someone later has to
explain a decision.

These labels do not establish that the reasoning was faithful. Reasoning models
often leave decisive factors out of their stated reasoning: Anthropic measured
hint verbalization of about 25% for Claude 3.7 Sonnet and 39% for DeepSeek R1, on
those two models ([arXiv 2505.05410](https://arxiv.org/pdf/2505.05410)).
`trustabl.cot.present` means reasoning occurred, not that it caused the answer,
and neither rule here claims more.

---

## Rule-by-rule defense

### OBS-013 - A reasoning label may be carrying the reasoning text itself (Severity: medium, Confidence: 0.6, Fix type: code)

**What we detect:**  
`repo_otel_labels_reasoning_unhashed: true`. A string literal under
`trustabl.cot.`, or the library's own constant for a key (`keys.COT_TEXT_FP`,
`COT_TEXT_FP`), passed as the first argument of `set_attribute` / `setAttribute`,
or as a key of the mapping passed to `set_attributes` / `setAttributes`, in a
non-test Python or TypeScript/JavaScript file, whose value could be the reasoning.
The key need not be one the library defines: `trustabl.cot.text` is the worst case
and no table of known keys would name it. These do not fire: the flag and enum keys
`trustabl.cot.present` and `trustabl.cot.mode`; a literal; a value whose expression
shows a hash (`canonical_fp`, `canonicalFp`, `sha256`, `hexdigest`, `.digest(`,
`hashlib`, `createHash`, `hash(`, `fingerprint`); and a plain name ending in `fp` or
`hash`. A Python f-string and a TypeScript template string can hold anything, so
they fire, and so does `summarize_digest(text)`, because a digest of the reasoning
is usually a summary of it.

**Why it is flaggable:**  
The keys promise every reader a hash, an enum or a flag. `mark_reasoning` keeps
that promise mechanically, by hashing the text and dropping it. A hand-written
value keeps it only by discipline, and the mistake is one identifier long:
`set_attribute("trustabl.cot.text_fp", thinking)` compiles, runs, and exports the
chain of thought. This is the one place the reasoning labels part ways with
OBS-006..008, which credit a hand-written `trustabl.*` key: a hand-written run id
cannot leak anything, and a hand-written reasoning value can.

**Real-world consequence:**  
- A developer labels model spans by hand, following the key names in the attribute
  spec, and passes the provider's thinking text as the `text_fp` value. A support
  bot's reasoning, quoting customer account details, reaches a third-party tracing
  backend under long retention, on a key no redaction processor was told about.
- A team adds `trustabl.cot.text` to make debugging easier in staging, and the
  environment check around it is removed in a later refactor. Production spans now
  carry the system prompt and every retrieved document the model reasoned over.

**Why severity is medium and not high:**  
OBS-003 sits at medium for an explicit switch that certainly sends content; this
is the same exposure with the value unproven, since the scanner sees an expression,
not what it holds at run time. It is not high because the data goes to the team's
own tracing backend rather than to an attacker, and because the repo may be
hashing in a way the expression does not show. It is not low because when the
finding is right, the most sensitive text in the run is leaving under a key built
to be trusted.

**Fix type: code.**  
Replace the hand-written attribute with a `mark_reasoning` call.

**Confidence 0.6:**  
The 0.4 gap:
- **A hash the expression does not show.** `value = compute(text);
  span.set_attribute(keys.COT_TEXT_FP, value)` fires, though `value` may be a good
  fingerprint. This is the largest false-positive source, and the fix is cheap
  either way.
- **A number under an invented key.** `trustabl.cot.token_count` holding an integer
  variable fires. It is not reasoning text, but it is still wrong: that concept is
  `gen_ai.usage.reasoning.output_tokens`, and a second key for it is what the
  attribute spec's rule 3 forbids.
- **False negatives by naming.** A variable called `reasoning_hash` that actually
  holds the text is credited. Name matching only ever declines to report, so a
  miss here is silent, not wrong in the other direction.
- **A key the scanner cannot read.** A key in a project's own constant under another
  name, or built from a template string, is not recorded, so a raw value written that
  way does not fire.

---

### OBS-014 - A model is set to reason, but no span records that it did (Severity: low, Confidence: 0.6, Fix type: code)

**What we detect:**  
All of `repo_otel_labels_implemented: true` (the run's end is recorded and, when
the repo ships a tool the model calls, a tool span is labelled),
`repo_model_reasoning_enabled: true`, and
`repo_otel_labels_reasoning_labelled: false`. A reasoning option is a keyword
argument or object key named `thinking`, `reasoning`, `reasoning_effort`,
`reasoningEffort`, `max_thinking_tokens`, `maxThinkingTokens`, `thinking_config`,
`thinkingConfig`, `anthropic_thinking`, `openai_reasoning_effort` or
`google_thinking_config`, with a value that does not leave it off (`False`, `None`,
`0`, `"none"`, `{"type": "disabled"}`, `{"type": "between_tools"}`,
`{"effort": "none"}`, a budget of `0`). `thinking` and `reasoning` are also plausible
names for a UI flag or a field of a project's own model, so they count only in the
shape a provider's option takes: as a keyword argument, a dict or a call
(`reasoning=Reasoning(effort="high")`), and as an object key, an object. That leaves
`setState({ thinking: true })` and `Verdict(reasoning=text)` out. `reasoning=True`
also counts, because it is CrewAI's documented switch. A label is a `mark_reasoning` /
`markReasoning` call, or any `trustabl.cot.*` key written by hand. Test files count
for neither the option nor the label. The rung itself,
`repo_otel_labels_implemented`, is shared with OBS-008 and does count them, so a repo
that labels runs only in its tests can draw this rule.

The rule is gated on the rung below it rather than on
`repo_observability_initialized` like OBS-006..012. A labelled run already shows
the team expects spans, and tracing started outside the parsed source
(`opentelemetry-instrument`, an environment switch) should not silence this.

**Why it is flaggable:**  
The repo has made both decisions that make this label cheap and useful: it labels
its runs, and it pays for reasoning. What is missing is the one call that connects
them. Without it a trace cannot say which model calls reasoned, cannot show that
two runs reasoned alike, and offers no span to match a reasoning text to when one
is captured later under an opt-in. The token count, where the instrumentation
records it, says the model spent tokens and nothing else about the step.

**Real-world consequence:**  
- An agent approves a refund it should have escalated. The tool span shows the
  call and its fingerprints. An investigator asks whether the model reasoned first,
  and the trace cannot say whether that call was one of the reasoning ones.
- A team later adds opt-in capture for a behavioral check on early answering. The
  captured texts have nothing to join to, because no span carries a fingerprint, so
  the check runs over text that cannot be tied to the actions it should explain.

**Why severity is low and not medium:**  
Nothing is misrepresented and nothing leaks. It is a gap in depth of diagnosis,
which is where OBS-006 sits for the same reason, and the rule recommends a library
published by the authors of the scanner, so it should not outrank findings that are
defects in the agent.

**Fix type: code.**  
One `mark_reasoning` call on the span of each model call.

**Confidence 0.6:**  
The 0.4 gap:
- **An option that does not reach this model.** A repo with two model calls where
  only one reasons, labelled at neither, fires correctly; one where the option sits
  in unused code fires incorrectly.
- **A project's own keyword of the same name.** `summarize(reasoning_effort="low")`
  on a project's own function counts, and so does `Verdict(reasoning=explain(text))`,
  where the call looks like a config call. The gate on a repo already using the labels
  keeps this rare, not impossible.
- **Labels written where the scanner cannot see.** A wrapper around
  `mark_reasoning` in a vendored or generated file the scan skips, or a label
  written in Go, leaves the repo looking unlabelled.
- **No span to label.** A framework that calls the model with no span of its own
  gives this call nowhere to land. The fix text then needs a span first, which is
  OBS-006's territory.

---

## What this policy does not cover

- **Whether a label lands.** `mark_reasoning` is a silent no-op with no current
  span. A repo in that state passes both rules and writes no label. Only exporting
  one run and looking for `trustabl.cot.present` on the model span shows it.
- **Reasoning text elsewhere.** A `gen_ai.*` or vendor attribute holding the
  thinking text, a log line, or a message-content event is not read here. OBS-003
  covers the explicit capture switches and only those.
- **The library call being given the wrong text.** `mark_reasoning(span,
  text=answer)` writes a fingerprint of the answer and passes both rules. The
  library's documentation says to pass the reasoning, and nothing checks it.
- **Models that reason by default.** A model that reasons with no option set, or a
  reasoning option set by a settings variable, `**settings`, a config file or an
  environment variable, draws no OBS-014. These misses keep the rule silent rather
  than wrong.
- **Other parsed languages.** Python and TypeScript/JavaScript only, as with the
  rest of the otel-labels family. The Go binding, `MarkReasoning`, is not inspected.
- **Agents outside the listed SDKs.** A repo using only a bare provider client has
  no SDK token in `applies_to`, so neither rule evaluates there.
- **Faithfulness.** A labelled span says that reasoning occurred and which text it
  was. Whether that text explains the decision is a behavioral or causal question
  no static rule can answer.
- **What the text is.** A provider may return its raw reasoning, a summary, or
  nothing. The label fingerprints what it is given, and no rule can tell a summary
  from the reasoning it summarizes. OBS-014 asks only that a span records something.
- **Fingerprint strength.** A short or guessable reasoning text can be confirmed
  by anyone holding a candidate, and the fingerprint is truncated to 64 bits. That
  is a property of the design, not something either rule measures, and it is part
  of what the privacy review has to weigh.

---

## Recommendations beyond the fix

```python
import anthropic
from opentelemetry import trace

from agent_reliability_otel_labels import Run, mark_reasoning, mark_run_end

tracer = trace.get_tracer("travel-agent")
client = anthropic.Anthropic()


def answer(question: str) -> str:
    run = Run()
    with tracer.start_as_current_span("invoke_agent") as root:
        run.mark_start(root)
        try:
            with tracer.start_as_current_span("chat") as span:
                response = client.messages.create(
                    model="claude-opus-5-5",
                    max_tokens=16000,
                    thinking={"type": "adaptive", "display": "summarized"},
                    messages=[{"role": "user", "content": question}],
                )
                # This provider returns a summary, never the raw chain of thought,
                # so the mode is latent. Only the fingerprint leaves the process, and
                # an empty summary writes no false claim.
                summary = "".join(
                    block.thinking for block in response.content if block.type == "thinking"
                )
                mark_reasoning(span, text=summary, mode="latent")
            mark_run_end(root, exit_reason="final_answer")
        except Exception:
            mark_run_end(root, exit_reason="error")
            raise
    return "".join(block.text for block in response.content if block.type == "text")
```

1. **Assert no reasoning text in your own export.** Plant a recognisable string in a
   test run and fail the build if it appears in any exported attribute. The library
   tests this about itself; a wrapper or a stray `set_attribute` in your code is only
   caught by testing your own spans.
2. **Keep raw capture separate and explicit.** If a behavioral check needs the text,
   capture it under an opt-in to a store with its own retention and access rules, and
   use the fingerprint to join it back. Do not put it on the span "for now".
3. **Pass the token count when the instrumentation does not.** It lets a label say
   that a model reasoned even when the provider shows no text, and it fills
   `gen_ai.usage.reasoning.output_tokens` only when that key is empty.
4. **Declare `mode` only when you know it.** An omitted key says "unknown", which is
   honest. `explicit_cot` says the text is the reasoning itself, which overclaims on a
   provider that returns only a summary. Claude's current models, for one, never
   return the raw chain of thought, so a fingerprint there proves which summary the
   span saw and no more.
5. **Take the fingerprint default through a privacy review before rollout.** It is
   Trustabl's own design, not a published convention, and a regulated deployment
   should decide for itself whether a one-way, unsalted, 64-bit hash of reasoning
   text is acceptable on a span.
