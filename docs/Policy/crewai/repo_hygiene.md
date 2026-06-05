---
policy_id: crewai_repo_hygiene
category: crewai
topic: repo_hygiene
rules:
  - id: CREW-201
    severity: low
    confidence: 0.9
    scope: repo
    fix_type: config
references: [LLM06]
---

# Policy Rationale: CrewAI Repo Hygiene

**Policy ID:** `crewai_repo_hygiene`  
**File:** `crewai/repo_hygiene.yaml`  
**Rules:** CREW-201  
**Severities:** low  
**Fix types:** config  
**References:** LLM06 (Excessive Agency)

---

## What this policy covers

A single repo-scope rule that fires once per scan. **CREW-201** fires when the
repo uses CrewAI in code (predicate `repo_has_sdk_in_code` for `crewai`) but ships
no agent-guidance doc — neither `AGENTS.md` nor `CLAUDE.md` is present as a
discovered repo component (predicate `repo_component_present`, negated). It reads
the scan inventory, not any single file.

---

## Why a missing agent-guidance doc is a distinct concern for CrewAI projects

`AGENTS.md` is the cross-vendor convention an editing coding agent reads before it
acts on a repository. When neither it nor a `CLAUDE.md` is present, any agent that
opens this repo has no project-specific guidance on how its agents and tools must
be configured. For a CrewAI project specifically, that means nothing in-tree tells
the agent whether `allow_code_execution` or the `CodeInterpreterTool` are
permitted, how tools must be defined and guarded, whether delegation is allowed,
and what the local test and build commands are. The likely consequence is
generated code that violates the project's own safety contract — an agent
re-introducing `allow_code_execution=True` or a hand-rolled `subprocess` tool
because nothing taught it the local rules. This is a soft, preventive form of
excessive-agency risk (LLM06): the guardrail that should constrain an editing
agent's choices is simply absent, so the agent operates with more latitude than
the maintainers intend.

---

## Rule-by-rule defense

### CREW-201 — Project ships no agent-guidance doc (Severity: low, Confidence: 0.9, Fix type: config)

**What we detect:** a repo that uses CrewAI in code but has neither `AGENTS.md`
nor `CLAUDE.md` at the root (predicates `repo_has_sdk_in_code` + `not
repo_component_present`).

**Why it is flaggable:** without an in-tree guidance doc, an editing agent has no
project-specific rules to follow and will reproduce unsafe patterns the
maintainers would reject.

**Real-world consequence:** a developer asks a coding agent to "add a tool that
runs the build"; with no `AGENTS.md` stating that shell-running tools are
forbidden, the agent writes a `subprocess.run(..., shell=True)` tool and wires it
to a code-executing agent — exactly the patterns the other CrewAI rules flag.

**Why severity is low and not medium:** the absence of the doc causes no harm by
itself; it only raises the probability that *other* defects get introduced, so it
is a preventive nudge rather than a live vulnerability. **Fix type — config:**
the fix is adding a documentation file at the repo root — no application or tool
code changes. **Confidence 0.9:** presence of `AGENTS.md` / `CLAUDE.md` is an
unambiguous inventory check; the small gap covers projects that document agent
guidance somewhere the component scan does not recognize (a wiki, a nested doc).

---

## What this policy does not cover

- The *content* or *quality* of an `AGENTS.md`. An empty or stale file satisfies
  the rule; the rule checks presence, not whether the guidance is correct or
  followed.
- Guidance kept somewhere other than a root `AGENTS.md` / `CLAUDE.md` — a wiki, a
  `CONTRIBUTING.md`, or a nested per-package doc the component scan does not map
  to these names — counts as absent.
- Whether any agent actually reads the doc. The rule cannot verify that an
  editing agent honors the guidance.
- It is a repo-scope nudge, not a per-agent or per-tool check — it says nothing
  about the safety of any individual agent or tool in the repo.

---

## Recommendations beyond the fix

```markdown
<!-- AGENTS.md at the repo root -->
# Agent guidance

## Safety rules
- Code execution is **forbidden**: never set `allow_code_execution=True` or wire
  `CodeInterpreterTool`. Run code only in the external sandbox at `tools/sandbox`.
- Tools must not shell out (`subprocess`, `os.system`) and must not fetch
  model-supplied URLs without the allow-list in `net/guard.py`.
- Every mutating tool takes an `idempotency_key`.

## Commands
- Test: `pytest`
- Lint: `ruff check .`
- Build: `make build`
```

1. Add an `AGENTS.md` at the repo root (a `CLAUDE.md` also satisfies the rule).
2. State whether code execution is permitted and under what guard, how tools must
   be defined and constrained, and any required human-in-the-loop gates.
3. List the exact test, lint, and build commands so an editing agent can verify
   its own changes.
4. Keep it short and concrete so an editing agent can act on it without
   re-deriving the conventions — and keep it current as the safety contract
   evolves.
