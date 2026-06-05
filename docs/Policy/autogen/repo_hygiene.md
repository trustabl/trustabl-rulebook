---
policy_id: autogen_repo_hygiene
category: autogen
topic: repo_hygiene
rules:
  - id: AG2-201
    severity: low
    confidence: 0.9
    scope: repo
    fix_type: config
references: [LLM06]
---

# Policy Rationale: AutoGen Repo Hygiene

**Policy ID:** `autogen_repo_hygiene`  
**File:** `autogen/repo_hygiene.yaml`  
**Rules:** AG2-201  
**Severities:** low  
**Fix types:** config  
**References:** LLM06 (Excessive Agency)

---

## What this policy covers

A single repo-scope rule that fires once per scan. **AG2-201** fires when the
repo uses AutoGen in code (predicate `repo_has_sdk_in_code` for `autogen`) but
ships no agent-guidance doc — neither `AGENTS.md` nor `CLAUDE.md` is present as a
discovered repo component (predicate `repo_component_present`, negated). It reads
the scan inventory, not any single file.

---

## Why a missing agent-guidance doc is a distinct concern for AutoGen projects

`AGENTS.md` is the cross-vendor convention an editing coding agent reads before it
acts on a repository. When neither it nor a `CLAUDE.md` is present, any agent that
opens this repo has no project-specific guidance on how its agents and tools must
be configured. For an AutoGen project specifically, that means nothing in-tree
tells the agent whether code execution is permitted, whether the executor must run
in Docker, whether `human_input_mode` may be set to `NEVER`, and what the local
test and build commands are. The likely consequence is generated code that
violates the project's own safety contract — an agent wiring an executor with
`use_docker=False` or `human_input_mode="NEVER"` because nothing taught it the
local rules. This is a soft, preventive form of excessive-agency risk (LLM06):
the guardrail that should constrain an editing agent's choices is absent, so the
agent operates with more latitude than the maintainers intend.

---

## Rule-by-rule defense

### AG2-201 — Project ships no agent-guidance doc (Severity: low, Confidence: 0.9, Fix type: config)

**What we detect:** a repo that uses AutoGen in code but has neither `AGENTS.md`
nor `CLAUDE.md` at the root (predicates `repo_has_sdk_in_code` + `not
repo_component_present`).

**Why it is flaggable:** without an in-tree guidance doc, an editing agent has no
project-specific rules to follow and will reproduce unsafe patterns the
maintainers would reject.

**Real-world consequence:** a developer asks a coding agent to "add an executor
that runs the generated scripts"; with no `AGENTS.md` stating Docker is required,
the agent writes `code_execution_config={"use_docker": False}` — exactly the
pattern AG2-001 flags.

**Why severity is low and not medium:** the absence of the doc causes no harm by
itself; it only raises the probability that *other* defects get introduced, so it
is a preventive nudge rather than a live vulnerability. **Fix type — config:** the
fix is adding a documentation file at the repo root — no application or tool code
changes. **Confidence 0.9:** presence of `AGENTS.md` / `CLAUDE.md` is an
unambiguous inventory check; the small gap covers projects that document agent
guidance somewhere the component scan does not recognize.

---

## What this policy does not cover

- The *content* or *quality* of an `AGENTS.md`. An empty or stale file satisfies
  the rule; the rule checks presence, not whether the guidance is correct or
  followed.
- Guidance kept somewhere other than a root `AGENTS.md` / `CLAUDE.md` — a wiki, a
  `CONTRIBUTING.md`, or a nested per-package doc — counts as absent.
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
- Code execution must run in Docker (`use_docker=True`) and is never enabled on
  an `AssistantAgent` — route it through the executor proxy only.
- `human_input_mode="NEVER"` is forbidden on any code-executing agent.
- Group chats set `max_round`; executors set `max_consecutive_auto_reply`.
- Tools must not shell out or fetch model-supplied URLs without the net guard.

## Commands
- Test: `pytest`
- Lint: `ruff check .`
- Build: `make build`
```

1. Add an `AGENTS.md` at the repo root (a `CLAUDE.md` also satisfies the rule).
2. State whether code execution is permitted and under what guard (Docker,
   `human_input_mode`), how tools must be registered and constrained, and any
   required human-in-the-loop gates.
3. List the exact test, lint, and build commands so an editing agent can verify
   its own changes.
4. Keep it short and concrete, and keep it current as the safety contract
   evolves.
