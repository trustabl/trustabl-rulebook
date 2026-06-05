---
policy_id: vercel_ai_repo_hygiene
category: vercel_ai
topic: repo_hygiene
rules:
  - id: VAI-012
    severity: low
    confidence: 0.9
    scope: repo
    fix_type: config
references: [LLM06]
---

# Policy Rationale: Vercel AI SDK Repo Hygiene

**Policy ID:** `vercel_ai_repo_hygiene`  
**File:** `vercel_ai/repo_hygiene.yaml`  
**Rules:** VAI-012  
**Severities:** low  
**Fix types:** config  
**References:** LLM06 (Excessive Agency)

---

## What this policy covers

A single repo-scope rule that fires once per scan. **VAI-012** fires when the repo
uses the Vercel AI SDK in code (predicate `repo_has_sdk_in_code` for `vercel_ai`)
but ships no agent-guidance doc — neither `AGENTS.md` nor `CLAUDE.md` is present as
a discovered repo component (predicate `repo_component_present`, negated). It reads
the scan inventory, not any single file.

---

## Why a missing agent-guidance doc is a distinct concern for Vercel AI projects

`AGENTS.md` is the cross-vendor convention an editing coding agent reads before it
acts on a repository. When neither it nor a `CLAUDE.md` is present, any agent that
opens this repo has no project-specific guidance on how its tools and agents must
be configured. For a Vercel AI project specifically, that means nothing in-tree
tells the agent whether provider execution tools (anthropic `bash`/`computer`,
openai `localShell`/`codeInterpreter`, google `codeExecution`) are permitted, how
tools must be typed and guarded, whether `maxSteps`/`stopWhen` is required, and
what the local test and build commands are. The likely consequence is generated
code that violates the project's own safety contract — an agent wiring
`anthropic.tools.bash` or an untyped `dynamicTool` because nothing taught it the
local rules. This is a soft, preventive form of excessive-agency risk (LLM06): the
guardrail that should constrain an editing agent's choices is absent, so the agent
operates with more latitude than the maintainers intend.

---

## Rule-by-rule defense

### VAI-012 — Project ships no agent-guidance doc (Severity: low, Confidence: 0.9, Fix type: config)

**What we detect:** a repo that uses the Vercel AI SDK in code but has neither
`AGENTS.md` nor `CLAUDE.md` at the root (predicates `repo_has_sdk_in_code` + `not
repo_component_present`).

**Why it is flaggable:** without an in-tree guidance doc, an editing agent has no
project-specific rules to follow and will reproduce unsafe patterns the
maintainers would reject.

**Real-world consequence:** a developer asks a coding agent to "add a tool that
runs shell commands"; with no `AGENTS.md` stating provider execution tools are
forbidden, the agent wires `anthropic.tools.bash` into the loop — exactly the
pattern VAI-006 flags.

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
- Whether any agent actually reads the doc. The rule cannot verify that an editing
  agent honors the guidance.
- It is a repo-scope nudge, not a per-agent or per-tool check — it says nothing
  about the safety of any individual agent or tool in the repo.

---

## Recommendations beyond the fix

```markdown
<!-- AGENTS.md at the repo root -->
# Agent guidance

## Safety rules
- Provider execution tools (anthropic bash/computer/codeExecution, openai
  localShell/codeInterpreter, google codeExecution) are **forbidden**.
- Every `generateText`/`streamText` call sets `maxSteps` or `stopWhen`.
- Every tool has a `description` and a concrete Zod `inputSchema` — no
  `dynamicTool` or `z.any()` without in-handler validation.
- Tools must not shell out or `fetch` model-supplied URLs without the net guard.

## Commands
- Test: `pnpm test`
- Lint: `pnpm lint`
- Build: `pnpm build`
```

1. Add an `AGENTS.md` at the repo root (a `CLAUDE.md` also satisfies the rule).
2. State whether provider execution tools are permitted and under what guard, how
   tools must be typed and constrained, and any required human-in-the-loop gates.
3. List the exact test, lint, and build commands so an editing agent can verify
   its own changes.
4. Keep it short and concrete, and keep it current as the safety contract evolves.
