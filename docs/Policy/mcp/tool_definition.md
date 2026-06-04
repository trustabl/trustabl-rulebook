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
**Severities:** low, medium, low, low  
**Fix types:** code, code, code, code  
**References:** LLM06

---

## What this policy covers

The three surfaces an MCP server advertises across its connection boundary for
every tool it exposes — the tool's **description**, its **input schema** (derived
from parameter type annotations), and its **name**. These rules fire on Model
Context Protocol tool registrations: `@server.tool` / `@mcp.tool` decorators and
`.register_tool(...)` calls in Python, and `server.registerTool(name, {description,
inputSchema}, handler)` in TypeScript. MCP-001 fires when a Python registration has
no docstring and no explicit description (predicate `has_docstring: false`);
MCP-002 when the handler has parameters but none is type-annotated (`has_params:
true` with `has_typed_params: false`); MCP-003 when the tool name is one of a
closed set of vague verbs — `process`, `handle`, `run`, `do`, `execute`,
`perform`, `work`, `go`, `thing`, `stuff` (`name_in`); MCP-011 when a TypeScript
registration's `description` is empty or built from a non-literal expression
(`has_docstring: false`).

---

## Why tool definition hygiene is a distinct concern in agent tools

In a conventional library a function's name and signature are a convenience for
the developer who calls it; in an MCP server they are the *entire* contract a
connecting model uses to route. An MCP server publishes each tool's name,
description, and JSON input schema across a process and trust boundary to whatever
client connects, and the model on the far side reads that metadata, picks a tool by
name and description, and synthesizes the arguments from the schema. There is
**no human in that loop** to disambiguate a vague name or correct a fabricated
argument before the call lands.

This is strictly worse than the in-process SDK case (Claude, OpenAI, ADK) for two
structural reasons. First, the caller is **not code the server author controls** —
it is an external orchestrator, often a *different vendor's* agent, whose prompt,
routing heuristics, and even base model the author cannot see or tune. A
description that "the team knows what it means" is worthless to a model the team
never tested against. Second, an MCP server is frequently **mounted by many clients
at once and shared across multiple agents**, so a single weak definition degrades
tool selection for every consumer simultaneously, and an ambiguous name like
`process` collides far more easily with similarly-named tools from *other* servers
loaded into the same session — the model is choosing among the union of every
mounted server's tools, not just this one's.

When the description is missing, the connecting model must guess the tool's purpose
from the name alone, and under an ambiguous request it mis-selects — calling the
wrong tool, or the right tool with wrong arguments. When parameters are untyped,
MCP advertises a degraded schema (parameters fall back to an unconstrained type),
so the model fabricates loosely-typed values that the handler then mishandles or
crashes on. When the name is a generic verb, the router has no signal to
distinguish it. Each gap degrades selection precisely when the input is unclear —
which is exactly when correct routing matters most.

These are reliability and correctness failures rather than direct memory-safety
exploits, but in an agentic setting a mis-selected tool *is* an unintended action.
The cluster anchors to OWASP **LLM06 (Excessive Agency)**: weak tool boundaries let
a model — here, one the author does not even control — act in ways the author never
intended.

---

## Rule-by-rule defense

### MCP-001 — Tool has no description (Severity: low, Confidence: 0.9, Fix type: code)

**What we detect:**
A Python MCP tool registration (`@server.tool` / `@mcp.tool` / `.register_tool`)
whose handler function has no docstring and no explicit `description=` argument
(predicate `has_docstring: false`).

**Why it is flaggable:**
The MCP server publishes the docstring (or the explicit description) to connecting
clients as the text the model uses to decide whether to call the tool. With none,
every connecting model routes on the function name alone — and because the server
is shared, that gap degrades routing for all clients at once, not just one.

**Real-world consequence:**
An MCP server exposes `def lookup(q: str)` with no docstring next to `def search(q:
str)`. A connecting agent — possibly a different vendor's model the server author
never tested — cannot tell which retrieves what and picks wrong under an ambiguous
query, returning the wrong data with full confidence to a user nobody in the loop
can correct.

**Why severity is low and not medium:**
It degrades selection quality but rarely causes direct harm on its own, and a
well-named tool partially compensates. The impact is mis-routing, not
wrong-argument execution or a breach — so it stays low.

**Fix type — code:**
The fix is to add a one-line docstring (or a `description=` argument) to the
registration — an edit to the tool's source. No guardrail or sandbox change
addresses it.

**Confidence 0.9:**
A missing docstring is mechanically unambiguous. The one false positive is a
registration whose description is supplied through a `description=` argument that
discovery did not capture (uncommon); otherwise an absent docstring is exactly what
it looks like.

### MCP-002 — Tool has no type-annotated parameters (Severity: medium, Confidence: 0.85, Fix type: code)

**What we detect:**
An MCP tool handler that has at least one parameter where no parameter carries a
type annotation (`has_params: true` with `has_typed_params: false`). `self` / `cls`
are ignored.

**Why it is flaggable:**
MCP derives the tool's advertised input JSON schema from the handler's Python type
annotations. With none, the published schema is degraded — parameters fall back to
an unconstrained type — so connecting models have no constraint on argument shape
and send unvalidated inputs that frequently cause runtime errors inside the server.

**Real-world consequence:**
An MCP server exposes `def transfer(amount, to)` with no annotations. The advertised
schema constrains neither field, so a connecting model passes `amount="a lot"` or a
malformed account id; the handler then coerces it wrong or crashes mid-side-effect —
and because the failure happens *inside the shared server*, it can surface as a 500
to every client, not just the one that sent the bad call.

**Why severity is medium and not low:**
Untyped parameters cause *wrong-argument execution*, not merely mis-selection — the
tool actually runs with bad data and may fire a partial side effect before failing.
That is a strictly higher impact than the description and name rules, so it sits a
band above them. It is not high because the failure typically surfaces as a runtime
error rather than a silent breach.

**Fix type — code:**
The fix is to add type hints to every parameter (or pass structured inputs via a
Pydantic model / TypedDict so the published schema constrains them) — an edit to
the handler signature. No external config substitutes for the missing annotations.

**Confidence 0.85:**
The predicate is mechanically reliable, but a handler that derives its real schema
from a Pydantic model or an explicit schema argument supplied elsewhere can be safe
yet annotation-free in its signature — the principal false positive, and the reason
this holds at 0.85 rather than higher. A false negative is a parameter typed as
`Any`, which satisfies the predicate while giving the model almost no constraint.

### MCP-003 — Ambiguous tool name (Severity: low, Confidence: 0.85, Fix type: code)

**What we detect:**
An MCP tool whose registered name is one of a closed, curated set of vague verbs:
`process`, `handle`, `run`, `do`, `execute`, `perform`, `work`, `go`, `thing`,
`stuff` (predicate `name_in`).

**Why it is flaggable:**
A generic name carries no routing signal about the tool's intent. Because an MCP
server is consumed by clients the author does not control, an ambiguous name
degrades selection *everywhere the server is mounted*, and collides far more easily
with similarly-named tools exposed by other servers loaded into the same session —
the model is routing across the union of every mounted server's tools.

**Real-world consequence:**
An MCP server exposes a tool named `process`. A client also mounts a second MCP
server that exposes its own `process`. The connecting model now sees two tools
named `process` with no way to tell them apart from the name, and a request that
should hit one is a coin-flip for the router whenever the prompt does not name the
server explicitly — invoking the wrong server's side effect.

**Why severity is low and not medium:**
A clear description can rescue a vague name, so the impact is bounded and the rule
is a clarity nudge rather than a defect that breaks execution. It does not cause
wrong-argument execution the way MCP-002 does, so it stays a band below it at low.

**Fix type — code:**
The fix is to rename the tool to a verb-object form (`summarize_invoice`,
`fetch_weather`) — an edit to the registration. No external configuration renames a
tool.

**Confidence 0.85:**
The name list is curated, so every match is deliberate and false positives are
rare. The residual gap below higher confidence is the cross-server collision
framing the rule leans on: in a session where this is the *only* server and the
name is locally unambiguous, the finding is technically still a clarity issue but a
weaker one — and a domain where `run` or `execute` is genuinely the most
descriptive verb (e.g. a job-runner tool) is a possible, if uncommon, false
positive the static name match cannot rule out.

### MCP-011 — TypeScript MCP tool has no description (Severity: low, Confidence: 0.85, Fix type: code)

**What we detect:**
A TypeScript MCP registration —
`server.registerTool(name, {description, inputSchema}, handler)` — whose
`description` is empty or is built from a non-literal expression (predicate
`has_docstring: false`). Discovery captures the description only when that value is
a plain string literal; an omitted/empty `description` **and** one assembled from a
template string with `${...}`, an identifier, a member access, or a concatenation
are all recorded as empty and fire. Unlike the Python sibling MCP-001, which reads
the description from the handler docstring, the TypeScript SDK takes it as an
explicit key in the registration config object.

**Why it is flaggable:**
The MCP server passes this `description` to every connecting model as the primary
signal for deciding whether to call the tool. With it empty, the model routes on
the tool name alone — the exact mis-selection mechanism documented for the Python
sibling
[MCP-001](#mcp-001--tool-has-no-description-severity-low-confidence-09-fix-type-code),
and degraded for every client of the shared server simultaneously.

**Real-world consequence:**
A TypeScript server registers `registerTool("lookup", { description: "", inputSchema
}, handler)` next to a described `search` tool. Under an ambiguous query a
connecting agent cannot tell which retrieves what and picks wrong, returning the
wrong data with full confidence — and because the description is empty for every
client, no single consumer can be configured around it.

**Why severity is low and not medium:**
Like MCP-001 it degrades selection quality but rarely causes direct harm on its
own, and a well-chosen tool name partially compensates. It matches the Python
sibling's low severity for the same reason: mis-routing, not wrong-argument
execution.

**Fix type — code:**
The fix is to provide a concise `description` string literal in the registration
config — an edit to the `registerTool(...)` call site. No external config supplies
it.

**Confidence 0.85:**
Marginally below the Python sibling's 0.9. The detection is mechanically exact (a
literal description is captured, anything else reads as empty), so the firing
itself is unambiguous; the gap reflects that a description built at runtime from a
non-literal expression — a constant assembled from `const` fragments — is genuinely
present to the model yet captured as empty here, a false positive the literal-only
capture cannot rule out.

---

## What this policy does not cover

- Descriptions or names that are *present but misleading* — a docstring or
  `description` that describes the wrong behavior passes MCP-001 / MCP-011 yet
  mis-routes worse than an empty one, and no single-tool predicate can read intent.
- Parameter types that are present but *too loose* (`x: Any`, `data: dict`) — they
  satisfy MCP-002 while giving the connecting model almost no schema to constrain
  arguments.
- Overlapping tool *purposes* — two distinct, well-named, well-described tools that
  nonetheless do near-identical things will still confuse a router; that is a
  server-design issue no per-tool check sees.
- Cross-server name collisions where *both* colliding names are descriptive but
  identical (two servers each exposing a sensible `fetch_user`) — MCP-003 only fires
  on the curated vague-verb set, so a collision between two non-vague names escapes.
- Descriptions supplied to a Python registration via an explicit `description=`
  argument rather than the docstring may be captured as absent and fire MCP-001 as a
  false positive.
- For MCP-011: a TypeScript `description` assembled from a non-literal expression (a
  `const` reference, a template string, a concatenation) is real text the model
  reads, but the literal-only capture records it as empty and fires anyway.
- The trust-boundary risks specific to MCP that these hygiene rules do **not**
  touch: an unauthenticated or over-permissioned server, a tool that returns
  attacker-controlled text the calling model then treats as instructions
  (tool-output prompt injection), or a malicious server impersonating a trusted
  tool name. Those are server-authorization and injection concerns, not definition
  hygiene.

---

## Recommendations beyond the fix

```python
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("invoices")


@mcp.tool()
def fetch_invoice(invoice_id: str, include_lines: bool = False) -> dict:
    """Fetch a single invoice by its ID.

    Use this when the caller asks about one specific invoice and provides its
    ID. Returns the invoice header; set include_lines=True to also return line
    items. Does NOT search — use search_invoices for lookups by date or amount.
    """
    ...
```

The handler above gives every connecting client — including ones the author never
tested against — a name that states intent, a description written for the router
(when to use the tool *and when not to*), and a type-annotated signature that MCP
turns into a constraining input schema. Hardening beyond what the rules detect:

1. Write the description for the *external router*, not for your own team: name when
   to call the tool and, crucially, when **not** to (point at the sibling tool that
   handles the other case). The model reading it may be a different vendor's agent
   with no shared context.
2. Type every parameter and prefer narrow types (`Literal[...]`, an enum, a
   constrained `int`, or a Pydantic model) over `str` / `Any`, so the advertised
   JSON schema makes the model's argument space small and validates inputs *before*
   the handler runs.
3. Namespace tool names to your server's domain (`invoices_fetch`,
   `invoices_search`) so they do not collide with the same generic verb exposed by
   another MCP server mounted into the same session.
4. Validate and bound arguments inside the handler regardless of the schema —
   never trust that a connecting client respected the advertised types, because the
   inputs are fully model-controlled and arrive across a trust boundary.
5. Treat tool *output* as untrusted: do not embed raw, attacker-influenceable
   strings the calling model will read as instructions, and keep authorization on
   the server side rather than assuming a well-behaved client.
