---
policy_id: mcp_package_install
category: mcp
topic: package_install
rules:
  - id: MCP-210
    severity: high
    confidence: 0.5
    scope: repo
    fix_type: code
references: [LLM06]
---

# Policy Rationale: MCP Server Installs a Package from Tool Input

**Policy ID:** `mcp_package_install`  
**File:** `mcp/package_install.yaml`  
**Rules:** MCP-210  
**Severities:** high  
**Fix types:** code  
**References:** OWASP LLM Top 10:2025 — LLM06 (Excessive Agency)

> **Verification status.** GitHub advisory GHSA-wcjj-9m6g-2fr2 and the fix commit were read on 2026-11-26 through the advisory API and as raw page text. The NVD record for CVE-2026-59176 could not be retrieved (the site blocked the request) and was not read. **Not verified, and therefore not assumed:** installs by pip, uv, yarn or bun; and whether the value in any repository the rule reports comes from a tool parameter.

---

## What this policy covers

**MCP-210** reads TypeScript and JavaScript files that import an `@modelcontextprotocol` package for an `npm` or `pnpm` add or install whose specifier is built from a value, in a file with no `.test(`, `semver`, `.valid(` or `.satisfies(`. It is a repo-scope rule with one finding per call.

---

## Rule-by-rule defense

### MCP-210 — MCP server runs npm or pnpm install with a specifier built from a value (Severity: high, Confidence: 0.5, Fix type: code)

**What we detect:** `repo_mcp_server_installs_package_from_input` (an `execFileSync`, `execFile`, `spawn`, `spawnSync`, `execa` or `execaSync` call with `npm` or `pnpm`, an argument array holding `add`, `install` or `i`, and a later identifier, template, concatenation or member expression). Applies to `mcp` repositories.

**Why it is flaggable.** GitHub advisory GHSA-wcjj-9m6g-2fr2 shows a tool that built the specifier as `functype@` plus a string parameter and ran `execFileSync("pnpm", ["add", spec])`, and states that "because npm/pnpm package specifiers support file:, npm:, and other alias syntaxes, an attacker who can send an MCP tools/call request to this tool can cause the server to install an arbitrary local or remote package". The program ran with an argument array and no shell. The advisory is cited for those statements and nothing more.

**Real-world consequence:** a caller chooses the package that the server installs on the host, and the package can run code when it is installed or imported.

**Why severity is high:** The pack sets high and states no reasoning for it.

**Fix type — code:** the fix validates the value against a strict pattern before the command and rejects specifier syntax.

**Confidence 0.5:** the pack's explanation states these limits of the check:

- It reads TypeScript and JavaScript and the programs `npm` and `pnpm`; the advisory does not cover pip, uv or yarn.
- Any non-literal element counts; the rule does not show that the value comes from a tool parameter.
- A file with a `.test(` call, `semver`, `.valid(` or `.satisfies(` outside comments is not judged, and the rule does not check that the check covers the value.
- The dynamic import after the install in the advisory's code is not read.

**Field check, run on 2026-11-26** (prototype of the detector over cloned public repositories at the commits listed in the report `~/trustabl-reports/static-batch-2.md`; not a random sample; each repository was scanned once, with a 120 second cap). Sample: the 5 TypeScript MCP repositories named under MCP-204. 0 hits. **0 hits: precision is not measured.**


---

## What this policy does not cover

- Installs by pip, uv, yarn and bun.
- A command run through `exec` with one string.

---

## Recommendations beyond the fix

1. Validate versions against a strict pattern and reject `:`, `/`, `\`, `@` and whitespace.
2. Pass `--ignore-scripts` to the install.

---

## Sources

- GitHub advisory GHSA-wcjj-9m6g-2fr2: https://github.com/advisories/GHSA-wcjj-9m6g-2fr2 Retrieved 2026-11-26. Cited for the vulnerable code shape, the specifier statement and the recommended validation, and nothing more.
