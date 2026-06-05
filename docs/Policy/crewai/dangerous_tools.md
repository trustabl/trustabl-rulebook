---
policy_id: crewai_dangerous_tools
category: crewai
topic: dangerous_tools
rules:
  - id: CREW-106
    severity: high
    confidence: 0.7
    scope: agent
    fix_type: config
  - id: CREW-107
    severity: medium
    confidence: 0.7
    scope: agent
    fix_type: config
references: [LLM02, LLM06]
---

# Policy Rationale: CrewAI Dangerous Built-in Tools

**Policy ID:** `crewai_dangerous_tools`  
**File:** `crewai/dangerous_tools.yaml`  
**Rules:** CREW-106, CREW-107  
**Severities:** high, medium  
**Fix types:** config, config  
**References:** LLM02 (Sensitive Information Disclosure), LLM06 (Excessive Agency)

---

## What this policy covers

Agent-scope rules for two classes of high-risk `crewai_tools` built-ins wired
onto an `Agent`. **CREW-106** fires when the agent wires `FileReadTool` with no
`file_path=` pin (predicate: `agent_uses_hosted_tool_class` for `FileReadTool`
AND `not agent_hosted_tool_kwarg_present` for its `file_path` kwarg). **CREW-107**
fires when the agent wires any of the web-fetching / RAG built-ins that retrieve
a model-chosen URL — `ScrapeWebsiteTool`, `SeleniumScrapingTool`,
`WebsiteSearchTool`, `SerperDevTool`, `JSONSearchTool`, `PDFSearchTool`, or
`CSVSearchTool` (predicate `agent_uses_hosted_tool_class`). Both read the
agent's resolved tool edges, not any tool body.

---

## Why model-controlled file and URL targets are a distinct concern in CrewAI

Both rules describe the same failure: a built-in tool whose *target* is chosen
by the model at call time, on an agent whose prompt surface is model-reachable.
An unpinned `FileReadTool` reads whatever path the model names — so a prompt
injection can make it read `/etc/passwd`, `~/.ssh/id_rsa`, or the application's
secrets file. That arbitrary-file-read exposure is exactly what CVE-2026-2285
(path traversal in the file-read tool) describes. Pinning the tool to a specific
file at construction removes the model's control over the target, which is why
`FileReadTool(file_path="...")` is the safe form and does not fire.

The web-fetching built-ins (CREW-107) are a server-side request forgery surface.
Because the destination is model-controlled, a prompt injection can point a
scraper or RAG retriever at internal services or the cloud metadata endpoint
(169.254.169.254) to exfiltrate credentials — the exposure tracked as
CVE-2026-2286. There is a second-order channel too: the retrieved page content
re-enters the conversation as untrusted text, giving the fetched site its own
prompt-injection path into the agent. So the tool is both an outbound SSRF
primitive and an inbound injection vector in one.

---

## Rule-by-rule defense

### CREW-106 — Agent grants an unconstrained FileReadTool (Severity: high, Confidence: 0.7, Fix type: config)

**What we detect:** an `Agent` that wires `FileReadTool` without a `file_path=`
argument (predicates `agent_uses_hosted_tool_class` + `not
agent_hosted_tool_kwarg_present`).

**Why it is flaggable:** with no pinned path the tool reads any file the agent
process can see, at a path the model chooses — arbitrary file read on the model's
say-so, the CVE-2026-2285 exposure.

**Real-world consequence:** an agent given `FileReadTool()` to "read the project
README" is injected to read `~/.aws/credentials`; the contents flow back into the
model context and out to the caller.

**Why severity is high and not critical:** arbitrary file read is serious but is
read-only and bounded by the process's filesystem permissions; it is not the
unconditional code execution the engine reserves critical for. **Fix type —
config:** the fix is constructing the tool with a pinned `file_path=`, an
agent-wiring change. **Confidence 0.7:** the rule cannot tell whether the agent's
input is reachable by untrusted content, and an agent that legitimately needs to
read several validated paths (and does its own allow-listing) is over-flagged —
the gap that holds it at 0.7.

### CREW-107 — Agent wires a tool that fetches model-chosen URLs (Severity: medium, Confidence: 0.7, Fix type: config)

**What we detect:** an `Agent` that wires one of the listed scraper / search /
RAG built-ins (predicate `agent_uses_hosted_tool_class`).

**Why it is flaggable:** these tools issue outbound requests to a model-supplied
URL, an SSRF primitive (CVE-2026-2286), and feed the retrieved content back into
the conversation as untrusted text.

**Real-world consequence:** an agent with `ScrapeWebsiteTool()` is injected to
fetch `http://169.254.169.254/latest/meta-data/iam/security-credentials/`, and
the returned cloud credentials are exfiltrated through the model's next output.

**Why severity is medium and not high:** the impact depends on the network the
agent host sits in — an agent with no reachable internal services or metadata
endpoint, or behind an egress proxy, gets a much smaller blast radius than the
unconstrained file read of CREW-106, so the capability is flagged at medium.
**Fix type — config:** drop or constrain the tool at the agent, plus egress
controls — no tool source edit. **Confidence 0.7:** the rule flags the tool's
presence, not a proven reachable internal target, so it over-flags agents that
only ever fetch vetted external URLs or run behind a strict egress allow-list.

---

## What this policy does not cover

- A *pinned* `FileReadTool(file_path="...")` does not fire (by design) — but the
  rule does not verify that the pinned path is itself safe or non-sensitive.
- File read or URL fetch implemented by hand inside a `@tool` body rather than
  via these built-ins. Hand-rolled SSRF is caught by **CREW-005** (ssrf.md);
  there is no tool-scope CrewAI rule for hand-rolled arbitrary file read, so a
  custom file-reading tool body is a coverage gap.
- A custom subclass of any of these built-ins under a different class name, or a
  third-party scraper/RAG tool not in the listed set, is not matched.
- Whether the agent's prompt surface is actually reachable by untrusted input —
  both rules flag the capability grant, not a proven injection path.
- Egress and filesystem controls applied at the OS/container layer are invisible
  to the class-name match, so an agent that is in fact sandboxed still fires.

---

## Recommendations beyond the fix

```python
from crewai import Agent
from crewai_tools import FileReadTool

# Pin the file reader to the one file the agent needs; the model cannot
# redirect it. For web access, prefer a fixed-endpoint tool over an open scraper.
agent = Agent(
    role="Release notes writer",
    goal="Draft notes from the changelog",
    backstory="...",
    tools=[FileReadTool(file_path="docs/CHANGELOG.md")],  # pinned target
)
```

1. Construct `FileReadTool(file_path="...")` bound to the one file the agent
   needs. If it must read several files, validate every candidate against an
   allow-list of directories, resolve symlinks, and reject any path that escapes
   the intended root (`Path(p).resolve().is_relative_to(root)` — never string
   prefix matching).
2. For URL-fetching tools, validate every destination against an allow-list of
   hosts, reject private and link-local IP ranges (and redirects into them), and
   forbid raw model-supplied URLs. Put an egress proxy in front of the agent
   process that blocks the metadata endpoint and internal CIDRs.
3. Treat any retrieved page content as untrusted input — keep it out of the
   system prompt and do not let it silently expand the agent's tool permissions.
4. Prefer a purpose-built tool that fetches from a fixed, vetted set of
   endpoints over an open scraper or RAG retriever.
