---
policy_id: mcp_path_prefix_containment
category: mcp
topic: path_prefix_containment
rules:
  - id: MCP-204
    severity: high
    confidence: 0.5
    scope: repo
    fix_type: code
references: [LLM06]
---

# Policy Rationale: MCP Server Path Containment by String Prefix

**Policy ID:** `mcp_path_prefix_containment`  
**File:** `mcp/path_prefix_containment.yaml`  
**Rules:** MCP-204  
**Severities:** high  
**Fix types:** code  
**References:** OWASP LLM Top 10:2025 — LLM06 (Excessive Agency)

> **Verification status.** The Cymulate write-up, GitHub advisories GHSA-hc55-p739-j48w and GHSA-q66q-fx2p-7w4m, and arXiv 2610.22301 were read on 2026-11-26 as raw page text, and the fixed server source (tag 2025.7.1) was read from the repository. The NVD records for CVE-2025-53109 and CVE-2025-53110 could not be retrieved (the site blocked the request) and were not read. **Not verified, and therefore not assumed:** Python containment checks; that a client can supply the path in any repository the rule reports; and what share of reported checks sit behind another guard.

---

## What this policy covers

**MCP-204** reads TypeScript and JavaScript files that import an `@modelcontextprotocol/` package and flags a `startsWith` call on a path-like value whose argument names a directory and carries no separator. It is a repo-scope rule with one finding per call site.

---

## Rule-by-rule defense

### MCP-204 — Path containment check uses startsWith with a root that has no separator (Severity: high, Confidence: 0.5, Fix type: code)

**What we detect:** `repo_mcp_prefix_containment_unsafe` (a `startsWith` call whose receiver text names a path and whose single argument is a directory-like expression that is not a literal, contains no `sep` and no slash string, and is not a URL path). Applies to `mcp` repositories.

**Why it is flaggable.** The Cymulate write-up of CVE-2025-53109 and CVE-2025-53110 states that "a naive prefix-matching check lets any path that simply begins with the approved directory (e.g., /private/tmp/allowed_dir) bypass the filter". GitHub advisory GHSA-hc55-p739-j48w states that versions before 0.6.3 and 2025.7.1 "could allow access to unintended files in cases where the prefix matches an allowed directory". The server source at tag 2025.7.1 compares with `normalizedDir + path.sep` (or equality) and runs `fs.realpath` before the check. arXiv 2610.22301 names a "PT-002 prefix-match containment" class and reports that the filesystem server's check "admitted sibling directories sharing the allowed prefix". Each source is cited for those statements and nothing more.

**Real-world consequence:** a path that begins with the allowed directory's name, such as a sibling directory, passes the check and the server reads or writes outside the allowed tree.

**Why severity is high:** The pack sets high and states no reasoning for it.

**Fix type — code:** the fix compares against the directory with a separator appended and resolves the path first.

**Confidence 0.5:** the pack's explanation states these limits of the check:

- It reads TypeScript and JavaScript; Python containment checks are not judged.
- It reads files that import a package whose name starts with `@modelcontextprotocol/`; a helper in a file with no such import is not seen.
- Receiver and argument text are matched by word lists, so a check whose names fall outside the lists is not seen, and a root that gains its separator in an earlier statement is reported.
- It does not check whether the path was resolved with `realpath`, does not judge a check built with `path.relative`, and does not show that a client can supply the path.
- A call whose receiver or argument text contains `pathname`, `url`, `href`, `route` or `endpoint` is treated as a URL path and is not judged.

**Field check, run on 2026-11-26** (prototype of the detector over cloned public repositories at the commits listed in the report `~/trustabl-reports/static-batch-2.md`; not a random sample; each repository was scanned once, with a 120 second cap). Sample: 5 TypeScript MCP repositories scanned (`modelcontextprotocol/typescript-sdk` 5ee54ee, `bgauryy/octocode` c265e3f, `metatool-ai/metamcp` 05818ec, `mcp-use/mcp-use` bc8fb6f, `artokun/comfyui-mcp` f4c4077). Before the URL-path exclusion the rule reported 11 sites in 2 repositories. 2 sites in `mcp-use/mcp-use` compared URL `pathname` values; both were false positives, and the exclusion removed them (re-scanned, 0 sites). 9 sites in `artokun/comfyui-mcp` (`src/tools/skills-access.ts` and `src/orchestrator/panel-tools.ts`) call `packDir.startsWith(packsDir())` or `startsWith(root)` on a joined path with no separator; each matches the rule as written. The same functions validate the pack name against a pattern before the join, so a read of those lines does not show an exploitable path; the findings are matches of the pattern with a guard elsewhere. That repository was not re-scanned after the exclusion; its lines contain none of the excluded words. **Small sample: one repository with hits.**


---

## What this policy does not cover

- Python containment checks and Go or Rust equivalents.
- Symlink races and containment checks done with `path.relative`.

---

## Recommendations beyond the fix

1. Compare with the directory plus `path.sep`, or for equality, on a `realpath` result.
2. Run the check on the path that the file operation then uses.

---

## Sources

- Cymulate, CVE-2025-53109 and CVE-2025-53110 write-up: https://cymulate.com/blog/cve-2025-53109-53110-escaperoute-anthropic/ Retrieved 2026-11-26. Cited for the prefix-matching statement and the vulnerable and fixed code shapes, and nothing more.
- GitHub advisory GHSA-hc55-p739-j48w: https://github.com/advisories/GHSA-hc55-p739-j48w Retrieved 2026-11-26. Cited for the affected versions and the statement about prefix matching, and nothing more.
- GitHub advisory GHSA-q66q-fx2p-7w4m: https://github.com/advisories/GHSA-q66q-fx2p-7w4m Retrieved 2026-11-26. Cited for the symlink handling title and versions, and nothing more.
- arXiv 2610.22301: https://arxiv.org/abs/2610.22301 Retrieved 2026-11-26. Cited for the PT-002 prefix-match class name and the sibling-directory statement, and nothing more.
