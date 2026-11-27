---
policy_id: mcp_secret_and_memory_flows
category: mcp
topic: secret_and_memory_flows
rules:
  - id: MCP-221
    severity: medium
    confidence: 0.4
    scope: tool
    fix_type: code
  - id: MCP-222
    severity: medium
    confidence: 0.4
    scope: tool
    fix_type: code
  - id: MCP-223
    severity: medium
    confidence: 0.3
    scope: tool
    fix_type: code
references: [LLM02, LLM06]
---

# Policy Rationale: MCP Tools That Return a Credential or Store One in Memory

**Policy ID:** `mcp_secret_and_memory_flows`  
**File:** `mcp/secret_and_memory_flows.yaml`  
**Rules:** MCP-221, MCP-222, MCP-223  
**Severities:** medium, medium, medium  
**Fix types:** code, code, code  
**References:** LLM02 (Sensitive Information Disclosure), LLM06 (Excessive Agency)

> **Verification status.** The arXiv abstracts for 2606.04141, 2604.03070 and 2610.25707 were read through the arXiv API on 2026-11-27. **Not read:** the full text of any of the three papers, so the pack cites their abstracts alone. **Not found, and therefore not assumed:** a true positive in public code. A scan of 21 public repositories on 2026-11-27 (Python and TypeScript MCP servers and agent repositories in the shared cache) produced no finding from these three rules, so precision and recall are not measured; the fixture is the sole place they are seen to fire. None of the three papers studies MCP tool return values or MCP memory tools.

---

## What this policy covers

MCP-221 and MCP-222 read the one-function taint pass (`tool_flow_reaches_sink` with source `secret_env` and sink `return_value`). The source is an environment variable read by a string-literal name that passes the secret-name test in `analysis.IsSecretEnvName`: one underscore-separated word from KEY, TOKEN, SECRET, PASSWORD and similar, and none from FILE, PATH, DIR, URL, HOST, ID, PUBLIC and similar. The sink is a return statement of the tool's own function. MCP-223 reads the same pass with source `param`, sink `memory_write`, and a parameter-name regex for credential words; the sink is the value of a store `put` or the data of a memory client `add` or `save_context`.

---

## Why these flows are flaggable

The arXiv study "Caught in the Act(ivation)" (arXiv:2606.04141) states that LLM agents place sensitive credentials in the same context window as untrusted retrieved content, which creates a direct path for indirect prompt injection to induce credential exfiltration. The arXiv study of agent skills (arXiv:2604.03070) reports that debug logging accounts for 73.5% of the vulnerabilities it found because agent frameworks feed standard output into the model's context window. The pack cites them for the exposure of a credential placed in the model's context, and nothing more. That a client places a tool result in the model's context is a property of how tool calls work; the pack states no reasoning beyond it.

The arXiv study "Whose Credential Is It?" (arXiv:2610.25707) reports that a store mixing logins of all users retrieves another user's credential, that agents in a stress test then used the foreign credential, and that recording the owner with each credential line prevents most misuse. The pack cites it for the exposure of credentials held in agent memory, and nothing more.

---

## Rule-by-rule defense

### MCP-221 — Python MCP tool returns a secret-named environment value (Severity: medium, Confidence: 0.4, Fix type: code)

**What we detect:** a Python `mcp_tool` with a flow from a credential-named environment variable, read through `os.environ[...]`, `os.environ.get(...)` or `os.getenv(...)` with a literal name, to a return statement. A slice such as `key[:4]`, a call into another function, a comparison and `bool(...)` end the flow.

**Why it is flaggable:** a secret that reaches the model's context is exposed to anything that can steer the model.

**Real-world consequence:** the credential is disclosed to the model, its provider chain and any prompt injection that asks for it.

**Severity:** the pack sets medium and states no reasoning for it.

**Fix type — code:** return the result of the call that uses the credential, or whether the variable is set, and not the value.

**Confidence 0.4:** The pack sets 0.4. The pack's explanation states these limits: just the tool's own function is read; a value passed to a helper is not followed; the name must be a literal; a slice or a masking call ends the flow; a check of whether the variable is set is not flagged; and names ending in a path, URL, host or identifier word are not read as credentials.

### MCP-222 — TypeScript MCP tool returns a secret-named environment value (Severity: medium, Confidence: 0.4, Fix type: code)

**What we detect:** a TypeScript or JavaScript `mcp_tool` with a flow from `process.env.NAME` or `process.env["NAME"]`, for a credential-named variable, to a return statement or to the expression body of an arrow function. A `.slice`, `.substring` or `.substr` call ends the flow.

**Why it is flaggable:** as for MCP-221.

**Real-world consequence:** as for MCP-221.

**Severity:** the pack sets medium and states no reasoning for it.

**Fix type — code:** return the result of the call that uses the credential, or whether the variable is set, and not the value.

**Confidence 0.4:** The pack sets 0.4. The pack's explanation states these limits: just the handler body is read; a value passed to another function is not followed; a secret read at module level is not tracked into the handler; a masked value, a comparison and `Boolean()` are not flagged; and names ending in a path, URL, host or identifier word are not read as credentials.

### MCP-223 — Python MCP tool writes a credential-named parameter into a memory store (Severity: medium, Confidence: 0.3, Fix type: code)

**What we detect:** a Python `mcp_tool` with a flow from a parameter named like `password`, `token`, `api_key`, `secret`, `credential`, `cookie`, `bearer` or `passphrase` to the value written by a store `put` or a memory client `add` or `save_context`.

**Why it is flaggable:** a credential held in a shared memory can be retrieved for a different user.

**Real-world consequence:** another user's credential is exposed to the agent and can be used for that user's account.

**Severity:** the pack sets medium and states no reasoning for it.

**Fix type — code:** keep credentials in a secret manager, and when one must be remembered scope the store to the user and record the owner with the entry.

**Confidence 0.3:** The pack sets 0.3. The pack's explanation states these limits: the rule does not know whether the namespace or the text names the owner, so a per-user store that records the owner is flagged; a client is recognized by a same-file binding to a mem0 constructor or a receiver name with `store`, `mem0` or `memory`; and a write made in a helper is not found.

---

## What this policy does not cover

- A credential read in one function and returned by another, a value held in a module constant, and an environment read through a name held in a variable.
- A whole-environment return such as `dict(os.environ)`; the pack has no verified source for it and does not read it.
- Other secret stores: files, keyrings and cloud secret managers.
- Log and print sinks in MCP tools; the cited skills study concerns script output in skills (see CSKILL-094), not an MCP server's output.
- Credentials in parameters with other names, and memory written through other clients.
- Tools in the OpenAI, Claude, CrewAI, ADK and Pydantic AI packs; a rule per pack is not built.

---

## Recommendations beyond the fix

1. Give a tool a reference to a credential and let the server resolve it, so the value is not in a parameter.
2. Keep memory per user and record the owner with each entry that holds anything secret.

---

## Sources

- "Caught in the Act(ivation): Toward Pre-Output and Multi-Turn Detection of Credential Exfiltration by LLM Agents", arXiv:2606.04141 (abstract read through the arXiv API). Retrieved 2026-11-27. Cited for the exposure of credentials kept in the same context window as untrusted content, and nothing more.
- "How Your Credentials Are Leaked by LLM Agent Skills: An Empirical Study", arXiv:2604.03070 (abstract read through the arXiv API). Retrieved 2026-11-27. Cited for the finding that agent frameworks feed standard output into the model's context, and nothing more.
- "Whose Credential Is It? How Owner Attribution in Agent Memory Shapes Cross-User Account Misuse", arXiv:2610.25707 (abstract read through the arXiv API). Retrieved 2026-11-27. Cited for the exposure of credentials in shared agent memory and the effect of recording the owner, and nothing more.
