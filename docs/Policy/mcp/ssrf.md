---
policy_id: mcp_ssrf
category: mcp
topic: ssrf
rules:
  - id: MCP-008
    severity: high
    confidence: 0.6
    scope: tool
    fix_type: code
  - id: MCP-013
    severity: high
    confidence: 0.6
    scope: tool
    fix_type: code
references: [LLM06, LLM02]
---

# Policy Rationale: MCP Server-Side Request Forgery

**Policy ID:** `mcp_ssrf`  
**File:** `mcp/ssrf.yaml`  
**Rules:** MCP-008, MCP-013  
**References:** LLM06 (Excessive Agency), LLM02 (Sensitive Information Disclosure)

> Shares the SSRF threat model with [openai_sdk/ssrf.md](../openai_sdk/ssrf.md).
> MCP-specific angle only.

---

## What this policy covers

An MCP tool handler issuing an HTTP request to a non-literal URL —
`has_dynamic_url_call` over the recognized clients (Python `requests`/`httpx`/
`urllib`; TypeScript `fetch`/`axios`/`got`/`undici` via the captured
`dynamic_url` handler fact). MCP-008 is the Python rule, MCP-013 the TypeScript
rule.

## Why SSRF is a server-boundary problem for MCP

An MCP tool argument arrives from a connecting client and is chosen by a model
from conversation context. If that value flows into the request URL, an attacker
who can shape the context steers the request at any host the **server** can reach
but the public internet cannot — cloud metadata endpoints (169.254.169.254) that
vend credentials, loopback admin APIs, internal services. The MCP server becomes
a proxy for requests the attacker could not otherwise make (LLM06), and the
response plus any request body leaks back across the trust boundary (LLM02).

---

## Rule-by-rule defense

### MCP-008 — Tool fetches a caller-controlled URL (SSRF) (Severity: high, Confidence: 0.6, Fix type: code)

**What we detect:** a Python handler whose outbound request URL is built from a
parameter or an interpolated string rather than a fixed literal.

**Why high / 0.6:** the consequence (credential theft via metadata, internal
pivot) is severe, so severity is high; confidence is 0.6 because "non-literal
URL" includes benign cases where the dynamic part is a fixed-base path segment,
and the rule cannot prove the value is attacker-reachable.

### MCP-013 — TypeScript MCP tool fetches a caller-controlled URL (SSRF) (Severity: high, Confidence: 0.6, Fix type: code)

**What we detect:** the same pattern in a TypeScript handler — a `fetch`/`axios`/
`got`/`undici` call whose first argument is a template string, identifier, or
concatenation rather than a string literal (captured `dynamic_url` fact).

**Why high / 0.6:** identical mechanism and calibration to MCP-008 on the
TypeScript SDK; a plain string-literal URL does not fire.

---

## What this policy does not cover

Whether the dynamic URL is genuinely attacker-controlled vs a fixed-base path;
allow-list validation the rule cannot see; DNS-rebinding and redirect-based SSRF
after an initially-safe host; and clients outside the recognized set.

---

## Recommendations beyond the fix

The Python safe pattern — host allow-list, pre-connect address-range check,
redirects disabled — is in
[claude_sdk/ssrf.md](../claude_sdk/ssrf.md#recommendations-beyond-the-fix) and
applies unchanged to MCP-008. MCP-013 is the TypeScript half, where the same
controls have different names:

```typescript
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { lookup } from "node:dns/promises";
import { z } from "zod";

// Rejects loopback, link-local, and private ranges in BOTH address families.
import { assertPublicAddress } from "./net-guard.js";

const server = new McpServer({ name: "reports", version: "1.0.0" });

server.tool(
  "fetch_report",
  // The host is the security boundary, so it is an enum — not a free string.
  { host: z.enum(["api.example.com", "data.example.com"]), path: z.string() },
  async ({ host, path }) => {
    for (const { address } of await lookup(host, { all: true })) {
      assertPublicAddress(address);
    }
    const res = await fetch(`https://${host}/${path.replace(/^\/+/, "")}`, {
      redirect: "manual",                      // an allowed host must not bounce us inward
      signal: AbortSignal.timeout(10_000),
    });
    const body = (await res.text()).slice(0, 500_000);
    return { content: [{ type: "text", text: body }] };
  },
);
```

MCP-specific additions:

1. **Expect the rule to keep firing.** Both MCP-008 and MCP-013 match a
   non-literal URL, and every allow-listed implementation above still builds its
   URL from a variable — the sample here would fire MCP-013 as written. That is
   the 0.6 confidence doing its job: the finding asks you to show the
   containment, and the allow-list is the answer. Suppress it on the tool once
   the guard is real; do not rewrite the guard to dodge the predicate.
2. Constrain the host in the input schema, not just in the handler body. A
   `z.enum` (or Python `Literal`) publishes the allow-list to the connecting
   client, so a model does not waste turns proposing hosts that will be
   refused, and the schema becomes the reviewable artifact.
3. Set `redirect: "manual"` — TypeScript's default is `follow`, so the
   Node/`undici` equivalent of the Python `follow_redirects=False` is opt-out,
   not opt-in. An allow-listed host that 302s to `169.254.169.254` defeats a
   check performed only before the first hop.
4. Have the address guard cover IPv6. A check written against dotted-quad
   strings passes `::1`, `fc00::/7`, `fe80::/10`, and IPv4-mapped forms like
   `::ffff:169.254.169.254` — a metadata endpoint reachable by a guard that
   only knows about IPv4.
5. Remember the MCP server is a network position, not just a process. The
   reason SSRF matters more here than in an in-process SDK tool is that the
   server usually sits somewhere with reachability the client deliberately does
   not have; block the metadata CIDR and internal ranges at the egress layer
   too, so a missed handler is not the only thing standing between a connecting
   client and the credential endpoint.
