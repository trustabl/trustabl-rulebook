---
policy_id: langchain_param_flow_sinks
category: langchain
topic: param_flow_sinks
rules:
  - id: LC-204
    severity: high
    confidence: 0.4
    scope: tool
    fix_type: code
  - id: LC-205
    severity: medium
    confidence: 0.4
    scope: tool
    fix_type: code
references: [LLM02, LLM08]
---

# Policy Rationale: LangChain Tool Parameters at a Retrieval or Store Boundary

**Policy ID:** `langchain_param_flow_sinks`  
**File:** `langchain/param_flow_sinks.yaml`  
**Rules:** LC-204, LC-205  
**Severities:** high, medium  
**Fix types:** code, code  
**References:** LLM02 (Sensitive Information Disclosure), LLM08 (Vector and Embedding Weaknesses)

> **Verification status.** The GitHub advisories GHSA-5x6v-p487-7qh2 and GHSA-6hmw-9432-67qq
> were read through the GitHub advisories API on 2026-11-27. **Not found, and therefore not
> assumed:** a true positive in public code. The two LangChain tools in
> `langchain-ai/memory-agent` (commit `d825fc5`) and the four in
> `langchain-ai/retrieval-agent-template` (commit `64a9fe3`) produced no finding, and the ten
> tools in `langchain-ai/executive-ai-assistant` (commit `758db71`) produced none; the fixture
> is the sole place the rules are seen to fire. Precision and recall are not measured. The
> advisory for LC-204 concerns the JavaScript package `@langchain/redis`, and this rule reads
> Python tools. Whether the Python vector stores escape filter values is not checked.

---

## What this policy covers

This policy has two rules over `tool_source_reaches_sink`, which reads the flows that the
one-function taint pass records on a tool; the sole source is a parameter of the tool.

- **LC-204** (Python): the sink is the `filter`, `filters`, `where`, `expr`, `pre_filter` or
  `search_kwargs` argument of a vector-store search call (`similarity_search*`,
  `max_marginal_relevance_search`, `as_retriever`, and a `query`, `search`, `get` or `delete`
  call carrying one of those arguments).
- **LC-205** (Python): the sink is the namespace argument of `get`, `put`, `search`, `delete`
  or `list_namespaces`, or an async form, on a receiver whose name contains `store`.

Each rule fires once per tool, at the sink line. The flow is the same as in
`mcp_param_flow_sinks`: assignments, f-strings, concatenation, `format`, `join`, and dict, list
and tuple literals that hold the parameter.

---

## Why a parameter at these calls is flaggable

GitHub advisory GHSA-5x6v-p487-7qh2 (CVE-2026-105799) states that `@langchain/redis` "did not
properly escape values used to construct structured RediSearch TAG and TEXT filters", and that
"an application that passes attacker-controlled values into these filters could allow the
attacker to alter the resulting search query", which can expose documents outside the intended
scope where the filter is a tenant or document-access boundary. The pack cites it for that
mechanism and nothing more.

GitHub advisory GHSA-6hmw-9432-67qq (CVE-2026-115883) states that the LangGraph Postgres and
SQLite stores save a namespace as its labels joined with `.`, so `("tenant", "bob")` and
`("tenant.bob",)` map to one stored namespace, and that a caller who could pass such a label
could read, overwrite or delete items in another namespace. The pack cites it for that
mechanism and nothing more. The pack states no further reasoning for treating a parameter at
these calls as a signal.

---

## Rule-by-rule defense

### LC-204 — LangChain tool parameter is built into a vector-store filter (Severity: high, Confidence: 0.4, Fix type: code)

**What we detect:** a Python `langchain_tool` with a flow from a parameter to a filter argument
of a vector-store call, including a parameter placed as a dict value.

**Why it is flaggable:** the model chooses the value, and a filter can carry the tenant or
access boundary.

**Real-world consequence:** a search returns documents outside the caller's scope when the
value alters the filter.

**Severity:** the pack sets high and states no reasoning for it.

**Fix type — code:** take the tenant value from the authenticated session, check any parameter
that must appear in a filter, and use structured filter objects.

**Confidence 0.4:** The pack sets 0.4. The pack's explanation states these limits: a parameter in
a dict value is flagged, including a plain pass-through that the store escapes; just the tool's
own function is read; a filter built in a helper or from a class attribute is not seen; a cast,
an annotation and an `if` test end the flow; and the filter argument is matched by name.

### LC-205 — LangChain tool parameter reaches a LangGraph store namespace (Severity: medium, Confidence: 0.4, Fix type: code)

**What we detect:** a Python `langchain_tool` with a flow from a parameter to the namespace
argument of a store call.

**Why it is flaggable:** the model chooses the value, and a store keeps tenants apart by
namespace.

**Real-world consequence:** items in another namespace are read, overwritten or deleted when
the value collides with it.

**Severity:** the pack sets medium and states no reasoning for it.

**Fix type — code:** build the namespace from the authenticated user, check any value that must
come from a parameter, and reject `.`.

**Confidence 0.4:** The pack sets 0.4. The pack's explanation states these limits: a store is
recognized by a receiver name containing `store`; a namespace built in a helper or taken from
the run configuration is not seen; a cast, an annotation and an `if` test end the flow; and the
backend and library version are not known, so an in-memory store is flagged too.

---

## What this policy does not cover

- TypeScript LangChain tools. The engine computes the flows; no rule reads them for LangChain.js
  in this batch.
- A filter or namespace built in a helper, from a class attribute, or from the run
  configuration, and a parameter passed whole to another function.
- The library versions in use. The advisories are fixed in library releases, and this policy
  does not check versions.
- Other tool kinds that put a parameter at these calls.

---

## Recommendations beyond the fix

1. Keep tenant and user identifiers out of tool parameters and read them from the
   authenticated session on the server.
2. Update the LangGraph store packages and the vector-store integrations to releases that
   contain the advisory fixes.

---

## Sources

- GitHub advisory GHSA-5x6v-p487-7qh2, "LangChain: RediSearch Filter Injection via Unescaped
  Tag/Text Values" (CVE-2026-105799). Retrieved 2026-11-27. Cited for the mechanism of an
  unescaped value altering a filter used as an access boundary, and nothing more.
- GitHub advisory GHSA-6hmw-9432-67qq, "LangGraph: Namespace labels containing `.` reach other
  namespaces in Postgres and SQLite stores" (CVE-2026-115883). Retrieved 2026-11-27. Cited for
  the mechanism of a namespace label colliding with another namespace, and nothing more.
