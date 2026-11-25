---
policy_id: claude_skill_unpinned_install
category: claude_skill
topic: skill_unpinned_install
rules:
  - id: CSKILL-091
    severity: medium
    confidence: 0.5
    scope: skill
    fix_type: code
references: [LLM03]
---

# Policy Rationale: Skill Installs Without an Exact Version

**Policy ID:** `claude_skill_unpinned_install`  
**File:** `claude_skill/skill_unpinned_install.yaml`  
**Rules:** CSKILL-091  
**Severities:** medium  
**Fix types:** code  
**References:** LLM03 (Supply Chain)

> **Verification status.** The two papers below were read on 2026-11-25 in their arXiv HTML
> versions. **Not verified, and therefore not assumed:** how frequent these install forms are
> in published skills beyond the public sample in the Trustabl report for this batch; whether
> a given registry version has changed since a skill was reviewed; and how the papers' own
> detectors define "unpinned".

---

## What this policy covers

A skill can tell the agent to install a package, or ship a script that does. This policy has
one rule. **CSKILL-091** flags a skill whose shell code blocks or bundled scripts install or
run a package without an exact version, or pipe a remote script to a shell. It is skill scope
and fires once per skill, attributed to its `SKILL.md`.

---

## Rule-by-rule defense

### CSKILL-091 — Skill installs a package without an exact version or pipes a remote script to a shell (Severity: medium, Confidence: 0.5, Fix type: code)

**What we detect:**

- `pip`, `pip3`, `python -m pip`, `uv pip` or `pipx` `install` on a registry package that has
  no `==` pin; `uv tool install` on a package with no exact pin.
- `npm`, `yarn`, `pnpm` or `bun` `install`, `i` or `add` on a registry package with no exact
  semantic version (`@latest` and a range count as unpinned).
- `npx`, `bunx`, `pnpm dlx`, `uvx`, `uv tool run` or `pipx run` on such a package (this shares
  its version test with MCPCFG-003).
- `go install <module>@latest`.
- `curl` or `wget` piped to `sh`, `bash`, `zsh`, `dash` or `ksh`, and `sh <(curl ...)`.

Where it reads: fenced code blocks of `SKILL.md` tagged `bash`, `sh`, `shell`, `zsh`,
`console` or `terminal`, or untagged; and bundled script files with comments removed.
In a script, a line counts when it starts with the command or passes it to a process API
(`os.system`, `subprocess`, `exec`); an install named in a message, log line, assertion or
list item is not judged. Prose outside a code block and inline code spans are not read. Gated by
`skill_unpinned_install`.

What is not flagged: an exact pin, `pip install -r file`, `pip install -e .`, a path, a URL, a
git spec, a variable, `npm install` or `npm ci` with no package, and `curl` that is not piped
to a shell.

**Why it is flaggable.** What is installed or run is decided when the skill runs, not when it
was reviewed. The skills study (arXiv 2601.10338) lists "Unpinned Dependencies" (SC1, 156
skills) and "External Script Fetching" (SC2, 67 skills) among its supply-chain patterns, with
the example detection pattern `curl.*\|.*sh|wget.*\|.*bash`. The dependency study (arXiv
2607.01136) reports that skill "identities, versions, and provenance remain implicit", and
recommends "lockfile-like records for skill developers". Both papers are cited for those
statements and nothing more.

**Why severity is medium:** The pack sets medium and states no reasoning for it.

**Confidence 0.5:** the explanation states these limits: SKILL.md prose is not read; a
requirements file, lockfile, path, URL, git spec and variable are not judged; an install built
at run time is not seen; a pinned package is silent; registry changes after review are not
checked. An install command shown in a code block as an optional step counts the same as one
the skill requires.

---

## What this policy does not cover

- Installs described in prose or in non-shell code blocks.
- Install commands for other package managers (`apt`, `brew`, `cargo`, `gem`, `docker`).
- Lockfile contents and the integrity of a pinned version.
- Whether a piped remote script is hosted at a fixed commit.

---

## Recommendations beyond the fix

```bash
pip install requests==2.32.3
npm install left-pad@1.3.0
```

1. Pin each package to an exact version, or ship a lockfile and install from it.
2. Fetch a script to a file, check it against a known hash, then run the file.
3. Keep install steps in one reviewed setup script.

---

## Sources

Retrieved 2026-11-25.

- *Agent Skills in the Wild: An Empirical Study of Security Vulnerabilities at Scale*, arXiv
  2601.10338. Cited for the unpinned-dependency and external-script-fetching patterns, and
  nothing more.
- *Skills Are Not Islands: Measuring Dependency and Risk in Agent Skill Supply Chains*, arXiv
  2607.01136. Cited for the statement that skill versions and provenance are implicit, and
  nothing more.
