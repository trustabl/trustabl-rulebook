---
policy_id: claude_skill_script_output
category: claude_skill
topic: skill_script_output
rules:
  - id: CSKILL-094
    severity: medium
    confidence: 0.4
    scope: skill
    fix_type: code
references: [LLM02]
---

# Policy Rationale: Skill Scripts That Print a Credential

**Policy ID:** `claude_skill_script_output`  
**File:** `claude_skill/skill_script_output.yaml`  
**Rules:** CSKILL-094  
**Severities:** medium  
**Fix types:** code  
**References:** LLM02 (Sensitive Information Disclosure)

> **Verification status.** The arXiv abstract for 2604.03070 was read through the arXiv API on 2026-11-27. **Not read:** the full text, so the pack cites the abstract alone. **Not found, and therefore not assumed:** a true positive in public code. Skill directories in the shared cache (`google/adk-samples` at `252a57c`, the `plugins/retail` and `.agents` trees, 12 skills; and the skills of other cached repositories) produced no finding from this rule; precision and recall are not measured.

---

## What this policy covers

CSKILL-094 reads `BundledFile.PrintsSecret`, set by `analysis.SkillScriptPrintsSecret` for a Python script outside test paths: a credential-named environment value (literal name, `os.environ[...]`, `os.environ.get` or `os.getenv`) reaches `print` or `sys.stdout.write` inside one function or the module body. Module-level assignments are visible in the functions of the same file. The rule shares the secret-name test with MCP-221.

---

## Why these flows are flaggable

The arXiv study (arXiv:2604.03070) reports that debug logging accounts for 73.5% of the vulnerabilities in 520 affected skills because agent frameworks feed standard output into the model's context window. The pack cites it for that mechanism, and nothing more. The pack states no reasoning beyond it for why a printed value is a signal.

---

## Rule-by-rule defense

### CSKILL-094 — Bundled skill script prints a secret-named environment value (Severity: medium, Confidence: 0.4, Fix type: code)

**What we detect:** a Python script in a skill directory that prints a credential-named environment value. A slice ends the flow; output to standard error, to `logging` and by other scripts are not read.

**Why it is flaggable:** standard output of a skill script is fed to the model's context.

**Real-world consequence:** the credential is disclosed to the model and its provider chain.

**Severity:** the pack sets medium and states no reasoning for it.

**Fix type — code:** remove the print, or print whether the variable is set and not its value.

**Confidence 0.4:** The pack sets 0.4. The pack's explanation states these limits: Python scripts are the sole input; each function and the module body are read on their own with module-level assignments visible; a value passed to another function that prints it is not found; a slice ends the flow; and files under test paths are not judged.

---

## What this policy does not cover

- Shell, JavaScript and other script types.
- Output through `logging` or to standard error.
- Credentials read from files or through a variable-held name.
- Credentials that a script prints after passing them through another function.

---

## Recommendations beyond the fix

1. Debug output of a skill script should hold no environment values.

---

## Sources

- "How Your Credentials Are Leaked by LLM Agent Skills: An Empirical Study", arXiv:2604.03070 (abstract read through the arXiv API). Retrieved 2026-11-27. Cited for the finding that agent frameworks feed standard output into the model's context window, and nothing more.
