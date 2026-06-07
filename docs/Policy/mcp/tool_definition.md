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
  - id: MCP-015
    severity: low
    confidence: 0.85
    scope: tool
    fix_type: code
  - id: MCP-016
    severity: low
    confidence: 0.85
    scope: tool
    fix_type: code
  - id: MCP-017
    severity: low
    confidence: 0.85
    scope: tool
    fix_type: code
  - id: MCP-018
    severity: low
    confidence: 0.85
    scope: tool
    fix_type: code
  - id: MCP-019
    severity: low
    confidence: 0.85
    scope: tool
    fix_type: code
  - id: MCP-020
    severity: low
    confidence: 0.85
    scope: tool
    fix_type: code
  - id: MCP-021
    severity: low
    confidence: 0.85
    scope: tool
    fix_type: code
  - id: MCP-022
    severity: low
    confidence: 0.85
    scope: tool
    fix_type: code
references: [LLM06]
---

# Policy Rationale: MCP Tool Definition Hygiene

**Policy ID:** `mcp_tool_definition`  
**File:** `mcp/tool_definition.yaml`  
**Rules:** MCP-001, MCP-002, MCP-003, MCP-011, MCP-015, MCP-016, MCP-017, MCP-018, MCP-019, MCP-020, MCP-021, MCP-022  
**References:** LLM06 (Excessive Agency)

> Shares the structural-hygiene threat model with
> [openai_sdk/tool_definition.md](../openai_sdk/tool_definition.md). This
> document covers the MCP-specific angle only.

---

## What this policy covers

The structural hygiene of Model Context Protocol tool registrations — the
Python decorator forms (`@server.tool` / `@mcp.tool` / `.register_tool`,
predicate `mcp_tool` kind) and the TypeScript `@modelcontextprotocol/sdk`
`server.registerTool(...)` / `server.tool(...)` forms, the Go SDKs
(mark3labs/mcp-go's `mcp.NewTool(...)` and the official go-sdk's
`mcp.AddTool(server, &mcp.Tool{...}, fn)`), the official C# SDK's
`[McpServerTool]`-attributed methods, and the PHP SDKs' (official mcp/sdk +
community php-mcp/server) `#[McpTool]`-attributed methods. MCP-001/002/003 are
the Python rules; MCP-011 is the TypeScript description rule; MCP-015/016 are the
Go rules; MCP-017 (no description) and MCP-018 (ambiguous name) are the C# rules;
MCP-019 (no description) and MCP-020 (ambiguous name) are the PHP rules; MCP-021
(no description) and MCP-022 (ambiguous name) are the Rust rules (official rmcp
crate, `#[tool]`-attributed methods).

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

### MCP-015 — Go MCP tool has no description (Severity: low, Confidence: 0.85, Fix type: code)

**What we detect:** a Go MCP tool whose description is empty
(`has_docstring: false`, reading the captured `Description`) — a mark3labs
`mcp.NewTool("name", ...)` with no `mcp.WithDescription(...)` option, or an
official-SDK `mcp.Tool{...}` with no `Description` field.

**Why it is flaggable:** identical mechanism to MCP-001 / MCP-011 on the Go
SDKs — the description is what the server advertises to connecting clients as the
model's routing signal. Confidence 0.85 mirrors the other description rules; the
residual gap is a description supplied through a non-literal expression, captured
as empty.

### MCP-016 — Ambiguous Go MCP tool name (Severity: low, Confidence: 0.85, Fix type: code)

**What we detect:** a Go MCP tool whose name — the first argument to
`mcp.NewTool(...)`, or the `Name` field of an `mcp.Tool` — is in the fixed
ambiguous set (`process`, `handle`, `run`, ...) via `name_in`.

**Why it is flaggable:** identical to MCP-003 — an ambiguous name gives the model
no intent signal and collides across servers in a shared session, and the cost is
paid by every uncontrolled consumer of the published catalog.

### MCP-017 — C# MCP tool has no description (Severity: low, Confidence: 0.85, Fix type: code)

**What we detect:** an `[McpServerTool]`-attributed C# method with no co-located
`[Description("...")]` attribute (`has_docstring: false`, reading the captured
`Description`).

**Why it is flaggable:** identical mechanism to MCP-001 / MCP-011 / MCP-015 on
the official ModelContextProtocol C# SDK — `[Description]` is what the server
advertises to connecting clients as the model's routing signal. Confidence 0.85
mirrors the other description rules.

### MCP-018 — Ambiguous C# MCP tool name (Severity: low, Confidence: 0.85, Fix type: code)

**What we detect:** an `[McpServerTool]` method whose name (the method name — the
SDK default) is in the fixed ambiguous set (`process`, `handle`, `run`, ...) via
`name_in` (case-insensitive, so PascalCase `Process` matches).

**Why it is flaggable:** identical to MCP-003 / MCP-016 — an ambiguous name gives
the model no intent signal and collides across servers in a shared session.

### MCP-019 — PHP MCP tool has no description (Severity: low, Confidence: 0.85, Fix type: code)

**What we detect:** a `#[McpTool]`-attributed PHP method whose attribute carries
no `description:` argument (`has_docstring: false`, reading the captured
`Description`). The smacker tree-sitter-php grammar parses a single-line `#[...]`
attribute as a comment, so discovery reads the `description:` argument out of the
attribute's comment text.

**Why it is flaggable:** identical mechanism to MCP-001 / MCP-011 / MCP-015 /
MCP-017 on the PHP MCP SDKs — the attribute's `description:` is what the server
advertises to connecting clients as the model's routing signal. Confidence 0.85
mirrors the other description rules; the residual gap is a multi-line attribute
form, which discovery does not currently read.

### MCP-020 — Ambiguous PHP MCP tool name (Severity: low, Confidence: 0.85, Fix type: code)

**What we detect:** a `#[McpTool]` method whose name — the attribute's `name:`
argument, or the method name when that argument is omitted — is in the fixed
ambiguous set (`process`, `handle`, `run`, ...) via `name_in`.

**Why it is flaggable:** identical to MCP-003 / MCP-016 / MCP-018 — an ambiguous
name gives the model no intent signal and collides across servers in a shared
session, and the cost is paid by every uncontrolled consumer of the published
catalog.

### MCP-021 — Rust MCP tool has no description (Severity: low, Confidence: 0.85, Fix type: code)

**What we detect:** a `#[tool]`-attributed Rust method (official rmcp crate) with
no description (`has_docstring: false`, reading the captured `Description`). rmcp
derives a tool's description from **either** a `description = "..."` attribute
argument **or** the method's `///` doc comment, so discovery checks both — a tool
documented the idiomatic Rust way (a `///` comment, no attribute arg) is correctly
treated as *having* a description and does not fire.

**Why it is flaggable:** identical mechanism to MCP-001 / MCP-011 / MCP-015 /
MCP-017 / MCP-019 on the rmcp SDK — the description is what the server advertises
to connecting clients as the model's routing signal. Confidence 0.85 mirrors the
other description rules; the residual gap is a description supplied through a
raw-string or non-literal expression, captured as empty.

### MCP-022 — Ambiguous Rust MCP tool name (Severity: low, Confidence: 0.85, Fix type: code)

**What we detect:** a `#[tool]` method whose name — the attribute's `name = "..."`
argument, or the method name when that argument is omitted — is in the fixed
ambiguous set (`process`, `handle`, `run`, ...) via `name_in`.

**Why it is flaggable:** identical to MCP-003 / MCP-016 / MCP-018 / MCP-020 — an
ambiguous name gives the model no intent signal and collides across servers in a
shared session, and the cost is paid by every uncontrolled consumer of the
published catalog.

---

## What this policy does not cover

Whether a present description is *accurate*, whether a typed schema is *correct*,
and the low-level `Server` + `setRequestHandler` authoring shape (tools there are
returned from a `ListTools` handler, not named at a registration call site, so no
per-tool definition is extracted). Resource and prompt registrations
(`@mcp.resource` / `@mcp.prompt`, `registerResource` / `registerPrompt`) are not
yet discovered. For Go, untyped-params has no analog (Go is statically typed, so
there is no MCP-002 equivalent), the official SDK's handler-struct input schema
and metoro-io/mcp-golang's reflection-based `RegisterTool` are not yet extracted,
and body-fact rules (shell / SSRF / timeout) await Go AST predicates. For C#,
untyped-params likewise has no analog (C# is statically typed), the
`[McpServerTool(Name = "...")]` name override is not read, and body-fact rules
plus the Semantic Kernel `[KernelFunction]` / AutoGen `[Function]` shapes await
later work. For PHP, the multi-line `#[...]` attribute form is not read (the
grammar parses single-line attributes as comments), `#[McpResource]` /
`#[McpPrompt]` are not discovered, and body-fact rules await PHP AST predicates;
unlike Go and C#, PHP type hints are optional, so an untyped-params analog of
MCP-002 *is* meaningful — discovery already captures `HasTypedParams`, and that
rule is a deliberate fast-follow rather than not applicable. For Rust,
untyped-params has no analog (Rust is statically typed, and the input schema lives
in a separate `#[derive(JsonSchema)]` struct passed via `Parameters<T>`, which is
not yet resolved); raw-string descriptions, `#[tool]` on free functions outside an
`impl`, the `#[prompt]` / resource shapes, and body-fact rules await later work.
