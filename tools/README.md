# Rulebook tooling

Both tools read the shipped pack from a sibling `trustabl-rules` checkout
(override with `--rules-repo` or `$TRUSTABL_RULES_REPO`) and share one rule
loader (`check_rulebook.load_rules`), so they can never disagree about what
ships. Requires python 3.11+ and pyyaml.

## `build_book.py` + `make book` — PDF build

The PDF is a build artifact, never authored by hand. `build_book.py` projects the
per-policy rationale docs (chapters, grouped into `\part`s by SDK) plus a generated
rule-catalog appendix into one Pandoc-ready markdown; Pandoc + a LaTeX engine then
render the PDF. Per-doc front-matter is stripped and intra-rulebook `*.md` links are
flattened (they do not resolve inside a single PDF).

```bash
make book                      # gate -> index -> assemble -> render PDF
make book PDF_ENGINE=tectonic  # tectonic is the easiest LaTeX engine for CI
make assemble                  # just build/trustabl-rulebook.md (no toolchain needed)
make clean
```

Requirements for the render step: `pandoc` and a LaTeX engine (`xelatex` default,
or `tectonic`/`lualatex`). The assemble step needs only python + pyyaml, so the
markdown can be produced and inspected without the toolchain. Pandoc options live in
[book/pandoc.yaml](book/pandoc.yaml); output lands in `build/` (gitignored).

A cover is not wired yet — Pandoc generates a title page from the metadata in
`pandoc.yaml`. To add the designed cover (reusing the GitHub banner art), drop a
title-page PDF/image in and reference it via an `include-before-body` LaTeX page;
tracked as a follow-up.

## `gen_index.py` — index/appendix generator

Regenerates the `POLICY_INDEX.md` master index and the per-SDK
`<category>/POLICY_INDEX.md` files as a pure projection of the rule pack. The
index is generated, never hand-edited — that is what stops it drifting (it had
gone stale at 43 rules while 64 shipped). Risk score = severity_weight ×
confidence × 100 using the engine's weights (critical 1.0 / high 0.7 /
medium 0.4 / low 0.15 / info 0.05), one decimal, round-half-up.

```bash
python tools/gen_index.py            # write the 4 index files
python tools/gen_index.py --check    # CI: exit 1 if regeneration would change anything
```

Wire `--check` into CI next to the consistency gate so a rule added to the pack
without regenerating the index fails the build.

## `check_rulebook.py` — consistency gate

Cross-checks the shipped detection rules (the `trustabl-rules` pack) against the
rulebook's rationale docs. It is the rulebook analog of the engine's
`TestPolicyRules_AllRulesCovered` guard: it fails when the book drifts from the
rules users actually receive, so a polished PDF can never quietly go stale.

### What it enforces

1. **Coverage** — every rule in `trustabl-rules` has a rationale doc covering it.
2. **Consistency** — each doc's front-matter `severity` / `confidence` / `scope`
   matches the rule's YAML.
3. **Placement** — a rule is documented in the chapter (`category`/`topic`) where
   it actually lives, and docs do not reference rules that no longer exist.

It reads the YAML front-matter required on every `docs/Policy/<category>/<topic>.md`
(see [`docs/policy-rationale-doc-template-guide.md`](../docs/policy-rationale-doc-template-guide.md)).

### Usage

```bash
# Requires: python 3.11+, pyyaml. A sibling trustabl-rules checkout.
python tools/check_rulebook.py                       # ../trustabl-rules by default
python tools/check_rulebook.py --rules-repo /path/to/trustabl-rules
python tools/check_rulebook.py --strict              # docs without front-matter are errors, not warnings
```

`TRUSTABL_RULES_REPO` overrides the default rules-repo path. Exit code `0` = the
book is consistent with the pack; `1` = at least one error; `2` = the rules repo
was not found.

### Migration status

Docs without front-matter are reported as **warnings** (not errors) so the
migration can land incrementally. Once every doc carries front-matter, switch CI
to `--strict` to make missing front-matter a hard failure.

### CI

The gate runs automatically via [`.github/workflows/rulebook.yml`](../.github/workflows/rulebook.yml):
a `consistency` job (this gate `--strict`, `gen_index.py --check`, and a book
assemble smoke test) gates every PR, and a `build-pdf` job renders and uploads the
PDF artifact. The workflow checks out `trustabl-rules` into `.rules` and passes
`--rules-repo .rules`. If `trustabl-rules` is private, set the `RULES_REPO_TOKEN`
secret to a PAT with read access; for a public pack the default token suffices.
