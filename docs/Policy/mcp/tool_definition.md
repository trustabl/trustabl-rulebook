---
policy_id: mcp_tool_definition
category: mcp
topic: tool_definition
rules:
  - id: MCP-001
    severity: low
    confidence: 0.9
    scope: tool
    fix_type: code
  - id: MCP-002
    severity: medium
    confidence: 0.85
    scope: tool
    fix_type: code
  - id: MCP-003
    severity: low
    confidence: 0.85
    scope: tool
    fix_type: code
  - id: MCP-011
    severity: low
    confidence: 0.85
    scope: tool
    fix_type: code
references: [LLM06]
---

# Policy Rationale: MCP Tool Definition Hygiene

**Policy ID:** `mcp_tool_definition`  
**File:** `mcp/tool_definition.yaml`  
**Rules:** MCP-001, MCP-002, MCP-003, MCP-011  
**References:** LLM06 (Excessive Agency)

> Shares the structural-hygiene threat model with
> [openai_sdk/tool_definition.md](../openai_sdk/tool_definition.md). This
> document covers the MCP-specific angle only.

---

## What this policy covers

The structural hygiene of Model Context Protocol tool registrations — the
Python decorator forms (`@server.tool` / `@mcp.tool` / `.register_tool`,
predicate `mcp_tool` kind) and the TypeScript `@modelcontextprotocol/sdk`
`server.registerTool(...)` / `server.tool(...)` forms. MCP-001/002/003 are the
Python rules; MCP-011 is the TypeScript description rule.

## Why definition hygiene is sharper for MCP than for an in-process SDK

An MCP server publishes its tool catalog — names, descriptions, and input
schemas — across a transport to **whatever client and model connect to it**.
The author does not control, and often cannot see, the consuming agent. A weak
description or an unconstrained schema therefore degrades tool selection for
every consumer of the server, and an ambiguous name collides more easily with
similarly-named tools from other servers mounted in the same session. The model
routes on the published metadata; that metadata is the entire contract.

---

## Rule-by-rule defense

### MCP-001 — Tool has no description (Severity: low, Confidence: 0.9, Fix type: code)

**What we detect:** an MCP tool registration whose Python handler has no
docstring (predicate `has_docstring: false`). The docstring is the description
MCP advertises to connecting clients.

**Why it is flaggable:** with no published description, every connecting model
loses the primary signal for deciding whether to call the tool, producing
wrong-tool or skipped calls across all clients of the server. Confidence 0.9
reflects that the absence is mechanical and certain; the residual gap is a tool
that sets `description=` on the decorator instead of a docstring (captured in
`Config`, not the docstring), which would false-positive — kept at low severity
because the consequence is degraded routing, not a security failure.

### MCP-002 — Tool has no type-annotated parameters (Severity: medium, Confidence: 0.85, Fix type: code)

**What we detect:** a handler with parameters but no type annotations
(`has_params: true` and `has_typed_params: false`).

**Why it is flaggable:** MCP derives the published input JSON schema from the
handler's type annotations. Without them the advertised schema is unconstrained,
so connecting models send inputs the handler cannot rely on and runtime errors
surface inside the server. Medium severity: degraded validation is a
reliability and minor injection-surface concern, not a direct compromise.

### MCP-003 — Ambiguous tool name (Severity: low, Confidence: 0.85, Fix type: code)

**What we detect:** a tool named from a fixed ambiguous set (`process`,
`handle`, `run`, `execute`, ...) via `name_in`.

**Why it is flaggable:** an ambiguous name gives the model no intent signal and
collides across servers in a shared session. Because an MCP server's consumers
are not controlled by the author, the cost is paid everywhere it is mounted.

### MCP-011 — TypeScript MCP tool has no description (Severity: low, Confidence: 0.85, Fix type: code)

**What we detect:** a TypeScript `registerTool(name, {description, ...}, handler)`
(or legacy `tool(...)`) whose `description` is missing or empty
(`has_docstring: false`, reading the captured `Description`). A description built
from a non-literal expression is captured as empty and also fires.

**Why it is flaggable:** identical mechanism to MCP-001 on the TypeScript SDK —
the registration config's `description` is the model's routing signal. Confidence
0.85 (vs MCP-001's 0.9) reflects that the TypeScript capture can miss a
description supplied through an unusual expression shape.

---

## What this policy does not cover

Whether a present description is *accurate*, whether a typed schema is *correct*,
and the low-level `Server` + `setRequestHandler` authoring shape (tools there are
returned from a `ListTools` handler, not named at a registration call site, so no
per-tool definition is extracted). Resource and prompt registrations
(`@mcp.resource` / `@mcp.prompt`, `registerResource` / `registerPrompt`) are not
yet discovered.
