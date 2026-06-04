# trustabl-rulebook

Index and rationale docs for the [trustabl](https://github.com/trustabl/trustabl)
static analyzer's policy ruleset. Canonical YAML rules live in
[trustabl/trustabl-rules](https://github.com/trustabl/trustabl-rules) — this
repo links into them and explains the threat model behind each rule.

Coverage spans three agent SDKs plus a protocol-level rule family for the
Model Context Protocol:

- **Claude Agent SDK** (`CSDK-*`) — [claude_sdk/](claude_sdk/)
- **OpenAI Agents SDK** (`OAI-*`) — [openai_sdk/](openai_sdk/)
- **Google ADK** (`ADK-*`) — [google_adk/](google_adk/)
- **Model Context Protocol** (`MCP-*`) — [mcp/](mcp/) (rules ship; rationale docs not yet authored — see [coverage](#current-totals) below)

## What lives here

| Path                                                         | Purpose                                                       |
| ------------------------------------------------------------ | ------------------------------------------------------------- |
| [POLICY_INDEX.md](POLICY_INDEX.md)                           | Master table of every shipped rule across all SDKs            |
| `<sdk>/POLICY_INDEX.md`                                      | Per-SDK rule index                                            |
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

The engine ships **102 rules across 45 files** in
[trustabl-rules](https://github.com/trustabl/trustabl-rules). This rulebook
documents **88 of them across 37 rationale docs** — full rationale coverage of
the three agent SDKs (Claude Agent SDK, OpenAI Agents SDK, Google ADK). The
breakdown below counts **shipped rules per family**; the rightmost column flags
where rationale docs are still missing.

| Family                 | Tool   | Agent  | Subagent | Repo  | Shipped | Rationale docs |
| ---------------------- | ------ | ------ | -------- | ----- | ------- | -------------- |
| Claude Agent SDK       | 17     | 8      | 2        | 3     | 30      | 30 ✓           |
| OpenAI Agents SDK      | 21     | 9      | 0        | 2     | 32      | 32 ✓           |
| Google ADK             | 14     | 11     | 0        | 1     | 26      | 26 ✓           |
| Model Context Protocol | 14     | 0      | 0        | 0     | 14      | 0 — see gap    |
| **All**                | **66** | **28** | **2**    | **6** | **102** | **88**         |

**Coverage gap (honest):** the `mcp/` pack — 14 rules, `MCP-001`–`MCP-014`, all
tool-scope — ships in `trustabl-rules` and now appears in
[POLICY_INDEX.md](POLICY_INDEX.md), but **has no rationale docs yet** (no
`docs/Policy/mcp/` directory). Until those are authored, `tools/check_rulebook.py`
fails on the 14 missing-doc errors. Authoring them (threat models + OWASP
citations) is tracked separately.

Full breakdown: [POLICY_INDEX.md](POLICY_INDEX.md).

## Using the rulebook

This repo is **documentation only** — it contains no rule YAML and the trustabl
engine never reads it. The engine resolves rules from
[trustabl/trustabl-rules](https://github.com/trustabl/trustabl-rules): at scan
time it clones the configured ref and caches it under
`os.UserCacheDir()/trustabl/rules/<sha>/`. The rulebook exists so a human can
look up *why* a rule fires (the threat model and references) without reading the
engine source.

To run a scan against a different rules pack or pin a version, point the
**engine** at a `trustabl-rules` repository/ref with `--rules-repo` /
`--rules-ref` (or the `TRUSTABL_RULES_REPO` env var); `--no-rules-update` uses
the local cache only. See the trustabl engine README for the full flag list.

## Contributing a rule

A rule spans three repos. The YAML lives in `trustabl-rules`; the rationale
doc lives here; the test mirror lives in the engine.

1. Read the rule-authoring contract in
   [trustabl-rules/CLAUDE.md](https://github.com/trustabl/trustabl-rules/blob/main/CLAUDE.md)
   — required fields, per-scope `applies_to` values, ID conventions, severity
   guidance.
2. Add the YAML rule to `trustabl-rules` under `<sdk>/<topic>.yaml`.
3. Copy the template from
   [docs/policy-rationale-doc-template-guide.md](docs/policy-rationale-doc-template-guide.md),
   fill every section, and add the paired rationale **here** at
   `docs/Policy/<sdk>/<topic>.md`.
4. Mirror the rule into the engine repo's `testdata/rules-fixture/` with at
   least one fire case and one silent case (see the engine's
   `testdata/rules-fixture/CLAUDE.md`, "Add a rule for X").
5. Open the PRs. The rule appears in [POLICY_INDEX.md](POLICY_INDEX.md) once
   the rulebook PR merges.

## Companion repos

- [trustabl/trustabl-rules](https://github.com/trustabl/trustabl-rules) —
  canonical YAML rules pack. The engine loads this at runtime; rule edits
  land here.
- [trustabl/trustabl](https://github.com/trustabl/trustabl) — the analyzer
  binary that consumes the rules pack.
