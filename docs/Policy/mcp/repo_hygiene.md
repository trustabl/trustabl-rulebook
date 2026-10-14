---
policy_id: mcp_repo_hygiene
category: mcp
topic: repo_hygiene
rules:
  - id: MCP-201
    severity: low
    confidence: 0.9
    scope: repo
    fix_type: config
references: []
---

# Policy Rationale: MCP Server Repo Hygiene

**Policy ID:** `mcp_repo_hygiene`  
**File:** `mcp/repo_hygiene.yaml`  
**Rules:** MCP-201  
**Severities:** low  
**Fix types:** config  
**References:** none

> MCP-201 is one of the cross-SDK "missing agent-guidance doc" rules. The
> family rationale is in [claude_sdk/repo_hygiene.md](../claude_sdk/repo_hygiene.md).
> This document covers the MCP server case: what the guidance doc has to say
> when everything the repo exports crosses a trust boundary.

---

## What this policy covers

A repo-scoped check (`scope: repo`, `applies_to: mcp`). The project implements
an MCP server in code (`repo_has_sdk_in_code: [mcp]`) but ships no
agent-guidance doc (`not repo_component_present: [agents_md, claude_md]`).
The rule fires once per scan, against the repo manifest and inventory rather
than per tool. Either an `AGENTS.md` or a `CLAUDE.md` satisfies it. The rule
declares no `language`.

---

## Why a missing agent-guidance doc is a distinct concern in MCP server projects

`AGENTS.md` is the cross-vendor convention an editing coding agent reads before
it acts. With neither `AGENTS.md` nor `CLAUDE.md` at the repo root, any agent
that opens the repo has no project-specific guidance on how tools must be
registered, named, described, and schema-typed.

That matters more in an MCP server than in most projects. Everything the repo
exports crosses a trust boundary to whatever client and model connect to it,
and the tool name, description, and input schema are the entire contract those
consumers see.

A tool added without the local conventions does not fail in this repo. It
degrades tool selection in every downstream client, and the server's authors
are not the ones who observe it.

---

## Rule-by-rule defense

### MCP-201 — MCP server project ships no agent-guidance doc (AGENTS.md/CLAUDE.md) (Severity: low, Confidence: 0.9, Fix type: config)

**What we detect:**
Both conditions hold: the project implements an MCP server in code
(`repo_has_sdk_in_code: [mcp]`), and neither an `agents_md` nor a `claude_md`
component is present (`not: repo_component_present: [agents_md, claude_md]`).

**Why it is flaggable:**
The project implements an MCP server, and no guidance doc at the repo root tells
an editing agent the conventions its tool registrations must follow. Those registrations
are the whole contract the server publishes to its clients.

**Real-world consequence:**
A contributor asks a coding agent to add a tool to the server. With no
guidance doc, the agent registers it without the project's naming convention
and namespace prefix. Nothing fails in this repo. Every client that
connects now has a tool it is less able to select correctly, and the server's
authors do not see that happen.

**Fix type — config:**
The fix is a documentation file at the repo root, an `AGENTS.md` or a
`CLAUDE.md`. No tool or server source changes.

**Confidence 0.9:**
The pack sets confidence at 0.9 for this rule. It states no known false
positives, false negatives, or other limits for MCP-201.

---

## What this policy does not cover

- **The content of a guidance doc that is present.** The match tests whether an
  `agents_md` or `claude_md` component is present. Nothing in the predicate
  reads what the doc says.
- **Guidance files under other names.** The predicate lists only `agents_md`
  and `claude_md`.
- **The tool definitions themselves.** Whether each tool has a usable name,
  description, and schema is the subject of the per-tool rules in
  [tool_definition.md](tool_definition.md), not of this rule.

---

## Recommendations beyond the fix

````markdown
# AGENTS.md

## Tools
- Name every tool `billing_<verb>_<noun>`, e.g. `billing_find_invoices`.
- A description says what the tool does, what it returns, and when to call it
  instead of a neighboring tool. Write it for a client that knows nothing else
  about this server.
- Type every input in the schema. Enumerable values are enums, not prose.
- Destructive tools (`billing_void_invoice`, `billing_refund_charge`) require
  a `confirm: true` input and are listed in docs/destructive-tools.md.

## Commands
- Test: `make test`
- Lint: `make lint`
- Build: `make build`
````

1. **State the tool naming convention and namespace prefix.** The name is part
   of the contract every connecting client sees.
2. **Say what a description must cover.** Write it for a client that has no
   other context about this server.
3. **Say how input schemas must be typed.**
4. **List the destructive operations and what gates them.**
5. **Give the exact test, lint, and build commands.**
6. **Keep it short and concrete,** so an editing agent can act on it without
   re-deriving the conventions.
