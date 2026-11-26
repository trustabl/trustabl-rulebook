---
policy_id: agent_config_guidance_install
category: agent_config
topic: guidance_install
rules:
  - id: AGCFG-023
    severity: high
    confidence: 0.4
    scope: repo
    fix_type: config
references: []
---

# Policy Rationale: Agent Guidance Files That Direct Installs the Manifest Does Not Declare

**Policy ID:** `agent_config_guidance_install`  
**File:** `agent_config/guidance_install.yaml`  
**Rules:** AGCFG-023  
**Severities:** high  
**Fix types:** config  
**References:** none

> **Verification status.** The paper cited below was read on 2026-11-26 as an abstract
> through the arXiv API (`export.arxiv.org`), not as a full text. The figure the planning
> sheet quotes for that paper is not in the abstract and is not used. **Not verified, and
> therefore not assumed:** how the attack prompts in the paper are worded; whether the paper's
> attacks use a package index option; and whether real project files name an install that
> their manifest lacks. The index options are this pack's own extension.

---

## What this policy covers

Agent guidance files (AGENTS.md, CLAUDE.md, GEMINI.md, Cursor `.mdc` rules, Windsurf and Devin
rules, the GitHub Copilot instruction files) are read by coding assistants as instructions. The
pack loads for each scan, because the files it reads have no SDK import; the predicate does the
gating.

This policy has one rule. **AGCFG-023** flags a sentence in such a file that installs a package
no dependency manifest of that ecosystem declares, or points an install at a package index other
than the ecosystem default. It is repo scope and fires once per scan, attributed to the first
matching sentence. AGCFG-022 reads the same files for other instructions; the two conditions do
not overlap.

---

## Rule-by-rule defense

### AGCFG-023 - An agent guidance file directs an install the manifests do not declare (Severity: high, Confidence: 0.4, Fix type: config)

**What we detect:** in a guidance-file sentence, gated by
`repo_guidance_directs_unverified_install`:

- a `pip`, `uv`, `poetry` or `pdm` install naming a package that no `requirements*.txt`,
  `pyproject.toml` or `Pipfile` in the repo declares, or an `npm`, `pnpm`, `yarn` or `bun`
  install naming a package that no `package.json` declares (names are compared after the
  usual case and separator normalization);
- an `--index-url`, `--extra-index-url`, `-i`, `--registry`, `npm config set registry` or
  `registry=` setting whose URL host is not `pypi.org`, `files.pythonhosted.org`,
  `registry.npmjs.org`, `registry.yarnpkg.com` or `download.pytorch.org`.

Not flagged: a global install, a flag, a path, a URL, a requirements file, a placeholder, a
sentence with a word of refusal, and any ecosystem with no manifest in the repo.

**Why it is flaggable.** *Package Hallucination Attacks on Coding Agents through Prompt
Injection in Rule Files* (arXiv 2610.09264, submitted 7 October 2026) states in its abstract
that an attacker can inject malicious prompts into benign rule files "to induce coding agents to
replace legitimate dependencies with attacker-controlled packages". An install instruction the
manifest does not back is the form such a prompt would leave in a rule file. The paper is cited
for that problem class and nothing more. The substitution of one declared package for another,
which the paper describes, is not checked, because deciding that a name is a lookalike needs a
named source of package names.

**Real-world consequence:** an agent that follows the instruction installs a package, or uses an
index, that the maintainers did not review, and runs it with the access of the session.

**Why severity is high:** The pack sets high and states no reasoning for it.

**Fix type - config:** declare and pin the package in the manifest, or remove the instruction;
name a package index in the project's reviewed configuration file.

**Confidence 0.4:** the pack's explanation states these limits:

- Names are compared with parsed manifests, not lockfiles, so a transitive package is reported.
- A development tool that a project installs for contributors and keeps out of its manifest, and
  an internal package index, match and are false positives.
- A sentence with a word of refusal is skipped, and so is an install command that follows a
  determiner; other prose use of an install command can still match and is a false positive.
- The substitution of one declared package for another is not checked.

---

## What this policy does not cover

- Instructions other than installs (AGCFG-022) and hidden characters (AGCFG-009, AGCFG-013).
- Ecosystems other than the two listed (PyPI and npm).
- Install commands in scripts, Makefiles and CI files.

---

## Recommendations beyond the fix

1. Keep tooling installs in a documented contributor setup that is part of the manifest or a
   lock-checked script.
2. Pin versions and hashes for what the agent may install.
3. Review changes to guidance files in pull requests.

---

## Sources

- Package Hallucination Attacks on Coding Agents through Prompt Injection in Rule Files, arXiv
  2610.09264, abstract retrieved 2026-11-26. Cited for the problem class and nothing more.
