---
policy_id: agent_config_trust_remote_code
category: agent_config
topic: trust_remote_code
rules:
  - id: AGCFG-021
    severity: medium
    confidence: 0.5
    scope: repo
    fix_type: code
references: [LLM03]
---

# Policy Rationale: Model Loaded With trust_remote_code Enabled

**Policy ID:** `agent_config_trust_remote_code`  
**File:** `agent_config/trust_remote_code.yaml`  
**Rules:** AGCFG-021  
**Severities:** medium  
**Fix types:** code  
**References:** LLM03 (Supply Chain)

> **Verification status.** The keyword behavior below was read on 2026-11-26 as raw source
> text from the Hugging Face Transformers repository,
> `src/transformers/models/auto/configuration_auto.py` (the `trust_remote_code`
> docstring), on the `main` branch. The two arXiv papers that the source sheet names for this
> rule (2602.04653, 2610.22578) were read the same day; they describe chat-template and
> model-weight backdoors, do not mention `trust_remote_code`, and are not relied on.
> **Not verified, and therefore not assumed:** the behavior of other libraries that accept
> a keyword of the same name, and how Transformers versions other than `main` word it.

---

## What this policy covers

A call that loads a model with `trust_remote_code=True` lets the model repository supply
Python modeling files that run in the loading process. This policy has one rule.
**AGCFG-021** flags a `from_pretrained` call with that literal. It is repo scope and reports
one finding per matching call. The pack loads for each scan, because the file has no SDK
import; the rule's own predicate does the gating.

---

## Rule-by-rule defense

### AGCFG-021 — Model is loaded with trust_remote_code=True (Severity: medium, Confidence: 0.5, Fix type: code)

**What we detect:** a Python call to `from_pretrained` (any receiver) that passes
`trust_remote_code=True`. Gated by `repo_call_kwarg_matches`.

What is not flagged: `trust_remote_code=False`; a value from a variable, a configuration
file or a flag; calls other than `from_pretrained`, such as `pipeline`, `from_config` and
loaders in other libraries; TypeScript code; and files under a test path. A unpinned
revision and a custom chat template, which the source sheet also lists, are not judged.

**Why it is flaggable.** The Transformers docstring for `trust_remote_code` says that the
keyword controls whether to allow "custom models defined on the Hub in their own modeling
files", that it should be set to `True` for "repositories you trust and in which you have
read the code", and that it "will execute code present on the Hub on your local machine".

**Real-world consequence:** the repository's modeling code runs with the privileges of the
loading process, at load time. A load by name takes whatever revision the repository holds
when the call runs.

**Why severity is medium:** The pack sets medium and states no reasoning for it.

**Fix type — code:** the fix edits the call. The pack's fix is to use a natively supported
model and drop the keyword, or to review the repository's Python files, pass `revision` with
a full commit hash, and keep that load out of a process that holds production credentials.

**Confidence 0.5:** the pack's explanation states these limits of the check:

- It reads the literal `True` at a `from_pretrained` call; a value from a variable, a
  configuration file or a flag is not judged.
- It does not know whether the repository is the author's own, whether the revision is
  pinned, or whether the modeling files were reviewed, and a load from a local path is
  judged the same as a load from the Hub.
- Other calls and libraries are not judged, files under a test path are not read, and
  TypeScript is not read.

The pack states no other limits for this rule.

---

## What this policy does not cover

- `pipeline(..., trust_remote_code=True)` and loaders such as dataset loaders.
- An unpinned `revision` and custom chat templates.
- A flag or configuration value that later reaches `trust_remote_code`.

---

## Recommendations beyond the fix

1. Prefer models the library supports natively.
2. Pin `revision` to a full commit hash for any model that needs custom code, and review the
   modeling files at that revision.

---

## Sources

Retrieved 2026-11-26.

- Hugging Face Transformers, `src/transformers/models/auto/configuration_auto.py`,
  `github.com/huggingface/transformers`, `main` branch. Cited for the `trust_remote_code`
  description, and nothing more.
