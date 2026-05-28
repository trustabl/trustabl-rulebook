# trustabl-rulebook

Index and rationale docs for the [trustabl](https://github.com/trustabl/trustabl)
static analyzer's policy ruleset. Canonical YAML rules live in
[trustabl/trustabl-rules](https://github.com/trustabl/trustabl-rules) — this
repo links into them and explains the threat model behind each rule.

Coverage spans three agent SDKs:

- **Claude Agent SDK** (`CSDK-*`) — [claude_sdk/](claude_sdk/)
- **OpenAI Agents SDK** (`OAI-*`) — [openai_sdk/](openai_sdk/)
- **Google ADK** (`ADK-*`) — [google_adk/](google_adk/)

## What lives here

| Path                                                         | Purpose                                                       |
| ------------------------------------------------------------ | ------------------------------------------------------------- |
| [POLICY_INDEX.md](POLICY_INDEX.md)                           | Master table of every shipped rule across all SDKs            |
| `<sdk>/POLICY_INDEX.md`                                      | Per-SDK rule index                                            |
| `<sdk>/*.yaml`                                               | Rule definitions consumed by the trustabl engine              |
| [docs/Policy/](docs/Policy/)                                 | Paired rationale docs (threat model, detection, references)   |
| [docs/policy-rationale-doc-template-guide.md](docs/policy-rationale-doc-template-guide.md) | Authoring template for new rules + rationale docs             |

## ID scheme

ID prefix denotes SDK; numeric range denotes scope.

| Range  | Scope             |
| ------ | ----------------- |
| `NNN`  | tool              |
| `1NN`  | agent / subagent  |
| `2NN`  | repo              |

Risk score = `severity_weight × confidence × 100`. Weights: `low=0.15`,
`medium=0.40`, `high=0.70`. Higher = worse.

## Current totals

| SDK                 | Tool   | Agent  | Subagent | Repo  | Total  |
| ------------------- | ------ | ------ | -------- | ----- | ------ |
| Claude Agent SDK    | 7      | 2      | 1        | 0     | 10     |
| OpenAI Agents SDK   | 13     | 6      | 0        | 1     | 20     |
| Google ADK          | 8      | 5      | 0        | 0     | 13     |
| **All**             | **28** | **13** | **1**    | **1** | **43** |

Full breakdown: [POLICY_INDEX.md](POLICY_INDEX.md).

## Using the rulebook

The trustabl engine shallow-clones `trustabl/trustabl-rulebook@main` into its
local cache (`~/.cache/trustabl-rule-miner/`) and loads it as the active rule
pack — no local checkout required for end users.

To pin a local checkout (for iteration on rule edits), point the engine at
this directory via its rules-path flag. See the trustabl engine README for
the exact flag name.

## Contributing a rule

1. Read [CLAUDE.md](CLAUDE.md) for the rule-authoring contract — required
   fields, per-scope `applies_to` values, ID conventions, severity guidance.
2. Copy the template from
   [docs/policy-rationale-doc-template-guide.md](docs/policy-rationale-doc-template-guide.md)
   and fill every section.
3. Add the YAML rule under `<sdk>/<topic>.yaml` and the paired rationale at
   `docs/Policy/<sdk>/<topic>.md`.
4. Mirror the rule into the engine repo's `testdata/rules-fixture/` with at
   least one fire case and one silent case (see CLAUDE.md "Add a rule for X").
5. Open a PR. The rule appears in [POLICY_INDEX.md](POLICY_INDEX.md) once
   merged.

## Companion repos

- [trustabl/trustabl-rules](https://github.com/trustabl/trustabl-rules) —
  canonical YAML rules pack. The engine loads this at runtime; rule edits
  land here.
- [trustabl/trustabl](https://github.com/trustabl/trustabl) — the analyzer
  binary that consumes the rules pack.
