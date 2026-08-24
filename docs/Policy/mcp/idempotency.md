---
policy_id: mcp_idempotency
category: mcp
topic: idempotency
rules:
  - id: MCP-007
    severity: medium
    confidence: 0.55
    scope: tool
    fix_type: code
  - id: MCP-027
    severity: medium
    confidence: 0.5
    scope: tool
    fix_type: code
  - id: MCP-029
    severity: medium
    confidence: 0.55
    scope: tool
    fix_type: code
references: [LLM06]
---

# Policy Rationale: MCP Mutating-Tool Idempotency

**Policy ID:** `mcp_idempotency`  
**File:** `mcp/idempotency.yaml`  
**Rules:** MCP-007, MCP-027, MCP-029  
**References:** LLM06 (Excessive Agency)

> Shares the retry-safety threat model with
> [openai_sdk/idempotency.md](../openai_sdk/idempotency.md). MCP-specific angle
> only.

---

## What this policy covers

A mutating MCP tool — its name carries a side-effect prefix — that exposes no
idempotency-key parameter, detected by `all: [name_has_prefix: [...], not:
param_name_matches: {contains: [idempot], exact: [...]}]`.

**MCP-007** (Python) uses prefixes with a trailing underscore (`create_`,
`send_`, …) and looks for `request_id` / `txn_id` on the handler signature.

**MCP-027** (TypeScript) is the `@modelcontextprotocol/sdk` counterpart: the
same mutation prefixes without the trailing underscore (so `createCharge`
matches `create`), and the key is looked up on `inputSchema` (`idempotencyKey`,
`requestId`, `txnId`, plus the snake_case spellings).

**MCP-029** (PHP) mirrors MCP-007 on `#[McpTool]` methods: underscore prefixes
and `idempotency_key` / `request_id` / `txn_id` on the method signature.

All three are name-and-signature heuristics — they do not read the tool body.

## Rule-by-rule defense

### MCP-007 — Mutating tool has no idempotency key (Severity: medium, Confidence: 0.55, Fix type: code)

**What we detect:** a side-effect-named Python handler with no parameter that
looks like an idempotency key.

**Why it is flaggable:** MCP clients retry tool calls under timeouts and ambiguous
failures, and the same model may be re-driven to repeat an action. Without an
idempotency key the handler executes the mutation twice — a duplicate charge,
order, or message. The excessive-agency framing (LLM06) is that the tool performs
an irreversible side effect with no replay guard. Medium severity, and confidence
0.55 because the signal is name-based: a tool named `create_*` may be internally
idempotent, and a mutating tool with a non-obvious name is missed. The finding is
a prompt to confirm, not a proof.

**Fix type — code:** accepting an idempotency key and de-duplicating server-side
is a source edit.

### MCP-027 — TypeScript MCP mutating tool has no idempotency key (Severity: medium, Confidence: 0.5, Fix type: code)

**What we detect:** a TypeScript `server.registerTool(name, {inputSchema, ...},
handler)` (or legacy `server.tool(...)`) whose name starts with a mutation
prefix (`create`, `send`, `delete`, … — no trailing underscore, so both
`create_charge` and `createCharge` match) and whose `inputSchema` has no
parameter whose name contains `idempot` or is exactly `requestId` /
`request_id` / `txnId` / `txn_id`.

**Why it is flaggable:** identical retry-safety mechanism to MCP-007 on the
TypeScript MCP SDK. Connecting clients retry under timeouts; without a schema
field the model cannot even *pass* a key. Confidence 0.5 (five points below
MCP-007) because the prefix match is looser (bare `create` matches
`createReport` that only renders a PDF) and because a key threaded as a captured
closure rather than a schema field is invisible to `param_name_matches`.

**Fix type — code:** adding an `idempotencyKey` field to `inputSchema` and
forwarding it is a source edit.

### MCP-029 — PHP MCP mutating tool has no idempotency key (Severity: medium, Confidence: 0.55, Fix type: code)

**What we detect:** a `#[McpTool]`-attributed PHP method whose advertised name
starts with a mutation prefix (`create_`, `send_`, …) and whose signature has no
parameter whose name contains `idempot` or is exactly `request_id` / `txn_id`.

**Why it is flaggable:** identical to MCP-007 on the PHP MCP SDKs (official
mcp/sdk and community php-mcp/server). Confidence 0.55 matches MCP-007: the
signal is name-based, and PHP discovery already captures `ParamNames` from the
method signature so the heuristic is as sharp as the Python rule.

**Fix type — code:** accepting an `idempotency_key` parameter on the method and
de-duplicating server-side is a source edit.

---

## What this policy does not cover

Whether the side effect is genuinely non-idempotent; mutating tools whose names
carry no recognized prefix; server-side de-duplication achieved without a visible
key parameter; Go / C# / Rust MCP mutating tools (those surfaces have no
idempotency analogue in this pack yet).