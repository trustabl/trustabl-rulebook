---
policy_id: claude_skill_bundled_content
category: claude_skill
topic: skill_bundled_content
rules:
  - id: CSKILL-088
    severity: high
    confidence: 0.7
    scope: skill
    fix_type: code
  - id: CSKILL-089
    severity: high
    confidence: 0.6
    scope: skill
    fix_type: code
  - id: CSKILL-090
    severity: medium
    confidence: 0.6
    scope: skill
    fix_type: code
references: [LLM03, LLM06]
---

# Policy Rationale: Skill Bundled File Content

**Policy ID:** `claude_skill_bundled_content`  
**File:** `claude_skill/skill_bundled_content.yaml`  
**Rules:** CSKILL-088, CSKILL-089, CSKILL-090  
**Severities:** high, high, medium  
**Fix types:** code, code, code  
**References:** LLM03 (Supply Chain), LLM06 (Excessive Agency)

> **Verification status.** The four papers below were read on 2026-11-25 in their arXiv
> HTML versions (full text for 2601.10338, 2602.20156, 2607.02357, 2608.08468 and
> 2610.10612). The statements attributed to each are quoted or closely paraphrased from
> that text. **Not verified, and therefore not assumed:** how frequent these patterns are
> in published skills beyond the public sample in the Trustabl report for this batch; how
> any scanner in the papers is configured; and what a flagged script or file does when it
> runs.

---

## What this policy covers

A skill directory can hold scripts that the skill runs through Bash, and other files that
travel with it. A reviewer who reads `SKILL.md` and the scripts as text sees just what the
text shows. This policy covers three things a bundled file can hold that make that reading
incomplete or unsafe: a script that decodes a payload and runs it, a script that runs a
destructive host command, and a file that is not readable as text. Each rule is skill scope
and fires once per skill, attributed to its `SKILL.md`. Files under test paths (the
engine's path classification) are not judged.

---

## Rule-by-rule defense

### CSKILL-088 — Bundled skill script decodes a payload and runs it (Severity: high, Confidence: 0.7, Fix type: code)

**What we detect:** in a bundled script, with comments removed, on one line: `base64 -d`
or `--decode` piped to `sh`, `bash`, `zsh`, `dash`, `ksh`, `python`, `perl`, `ruby`, `node`,
`php` or `pwsh`; `eval` or `source` over a command that uses `base64 -d`; `sh <(base64 -d
...)`; and a call to `eval`, `exec` or `new Function` whose argument holds `b64decode`,
`b32decode`, `b85decode`, `a85decode`, `decodebytes`, `decompress`, `fromhex`, `unhexlify`,
`atob`, `codecs.decode`, or `Buffer.from(..., 'base64')`. Gated by
`skill_bundled_script_decodes_and_executes`.

**Why it is flaggable.** The code that runs is not in the file, so a reviewer cannot read
it. The skills study (arXiv 2601.10338) lists "obfuscated code" among its supply-chain
patterns (SC3, 55 skills), describes the example detection pattern
`base64\.b64decode.*exec|zlib\.decompress`, and counts SC3 among the "High severity
patterns" that "strongly suggest malicious intent or create immediate exploitation risk".
The paper's case study describes a skill whose "obfuscated code segments (base64-encoded)
injected post-install hooks". The paper is cited for the pattern class and nothing more;
the rule's own patterns are the list above.

**Why severity is high:** The pack sets high and states no reasoning for it.

**Confidence 0.7:** the explanation states these limits: a single line; a decoder on a
different line from the `eval`, a decode into a file that is run later and other encodings
are not matched; a match inside a string or heredoc counts; test paths are not judged; the
decoded content is not read.

### CSKILL-089 — Bundled skill script runs a destructive host command (Severity: high, Confidence: 0.6, Fix type: code)

**What we detect:** in a bundled script, with comments removed: `rm` with a recursive flag
whose target is exactly `/`, `~`, `$HOME` or `${HOME}` (optionally followed by `/*`);
`mkfs` and `mkfs.<type>`; `dd` with `of=` a block device (`/dev/sd*`, `hd*`, `vd*`, `xvd*`,
`nvme*`, `mmcblk*`, `disk*`, `rdisk*`); `shred` on one of those devices; the form
and `:(){ :|:& };:`. Gated by `skill_bundled_script_destructive_command`.

What is not flagged: a relative or nested target (`rm -rf ./build`, `rm -rf /tmp/work`,
`rm -rf ~/.cache/x`), a target held in a variable other than `HOME`, `dd` to a file or to
`/dev/null`, and deletes made through a language API.

**Why it is flaggable.** The skill-injection study (arXiv 2602.20156) shows, in its
"Full Delete" case, a skill script (a "file integrity check") that "actually executes
`rm -rf` to delete all user files", and reports that skill-file injections reach up to 80%
attack success with frontier models, including data exfiltration, destructive action and
ransomware-like behavior. The
SkillsMetric study (arXiv 2608.08468) reports a 0.0% detection rate for its "Host
destruction" class and notes that "destructive commands like `rm` are too common to flag
without massive false positives". That is why the rule matches the root, home and device
targets above and no relative target. Both papers are cited for those statements and
nothing more.

**Why severity is high:** The pack sets high and states no reasoning for it.

**Confidence 0.6:** the explanation states these limits: the listed forms and targets and no others;
a variable target, a language-API delete and a command built at run time are not matched; a
match inside a string counts; test paths are not judged.

### CSKILL-090 — Skill ships an archive, native binary, WebAssembly or bytecode file (Severity: medium, Confidence: 0.6, Fix type: code)

**What we detect:** a file in the skill directory (or, for a `SKILL.md` at the scan root,
in `scripts`, `bin`, `tools`, `references` and `assets`) that is an archive (`.zip`, `.tar`,
`.gz`, `.tgz`, `.bz2`, `.xz`, `.7z`, `.rar`, `.whl`, or the matching magic number), a native
binary (ELF, Mach-O, PE, `.so`, `.dll`, `.dylib`, `.exe`, `.class`, `.jar`, `.node`, `.o`,
`.a`), WebAssembly (`.wasm` or `\0asm`), or Python bytecode (`.pyc`, `.pyo`). The
document containers `.docx`, `.xlsx`, `.pptx`, `.dotx`, `.xltx`, `.potx`, `.odt`, `.ods`,
`.odp`, `.epub` and `.vsix` are skipped. Gated by `skill_bundled_file_is_opaque`. The check
reads the file name and the first 512 bytes; size and entropy are not measured.

**Why it is flaggable.** The PyCache Trap study (arXiv 2610.10612) pairs benign Python
source with a substituted bytecode cache "accepted by the loader" and reports 94-100%
attack success against seven scanners with "no semantic recognition of the cache-resident
behavior". The Cloak and Detonate study (arXiv 2607.02357) says that each surveyed scanner has
a blind-spot directory, file type, binary blob or bounded prompt context that it does
not inspect, and describes SFS packing, in which "the entire original skill is archived"
and a decoder script unpacks it when the agent runs the skill. Both papers are cited for
those statements and nothing more. They do not study ELF, Mach-O, PE or WebAssembly files;
those are listed because a reviewer cannot read them as text, which is the property the
rule states.

**Why severity is medium:** The pack sets medium and states no reasoning for it.

**Confidence 0.6:** the explanation states these limits: the name and the first bytes; document
containers are skipped; an archive with an unrecognised name and no magic number is not
found; what the file does is not examined; test paths are not judged.

---

## What this policy does not cover

- Decoding on a different line from the `eval`, other encodings, and a decode to a file that
  is run later (CSKILL-088).
- Relative, nested or variable delete targets, language-API deletes, and `chmod -R 777 /`
  and force pushes (CSKILL-089).
- The behavior of a binary, archive or bytecode file (CSKILL-090).
- Network egress and secret reads (CSKILL-010, CSKILL-011), hardcoded secrets (CSKILL-030)
  and install commands (CSKILL-091).
- Scripts without a recognised script extension; the engine classifies by extension.

---

## Recommendations beyond the fix

1. Ship scripts as readable source and build artifacts where they are used.
2. Review a skill's scripts as you would a dependency, and pin the skill to a commit.
3. Delete `__pycache__` and `.pyc` files before publishing a skill.
4. Name the one directory a cleanup script created, and check the variable that holds it.

---

## Sources

Retrieved 2026-11-25.

- *Agent Skills in the Wild: An Empirical Study of Security Vulnerabilities at Scale*,
  arXiv 2601.10338. Cited for the obfuscated-code pattern and its severity tier, and
  nothing more.
- *Skill-Inject: Measuring Agent Vulnerability to Skill File Attacks*, arXiv 2602.20156.
  Cited for the destructive-script example and the reported attack success, and nothing more.
- *SkillsMetric: Mapping the Detection Boundary of Static Analysis for Malicious Agent
  Skills*, arXiv 2608.08468. Cited for the host-destruction detection rate and the
  false-positive note on `rm`, and nothing more.
- *Cloak and Detonate: Scanner Evasion and Dynamic Detection of Agent Skill Malware*, arXiv
  2607.02357. Cited for the scanner blind spots and the archive-packing description, and
  nothing more.
- *PyCache Trap: The Inspection-Execution Gap in Agent Skill Scanners*, arXiv 2610.10612.
  Cited for the bytecode substitution result, and nothing more.
