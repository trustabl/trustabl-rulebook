---
policy_id: mcp_tool_description_hidden_text
category: mcp
topic: tool_description_hidden_text
rules:
  - id: MCP-036
    severity: medium
    confidence: 0.5
    scope: tool
    fix_type: code
  - id: MCP-037
    severity: medium
    confidence: 0.5
    scope: tool
    fix_type: code
references: [LLM01]
---

# Policy Rationale: Hidden Characters in MCP Tool Descriptions

**Policy ID:** `mcp_tool_description_hidden_text`  
**File:** `mcp/tool_description_hidden_text.yaml`  
**Rules:** MCP-036, MCP-037  
**Severities:** medium, medium  
**Fix types:** code, code  
**References:** LLM01 (Prompt Injection)

> **Verification status.** The Invariant Labs report, the Pillar Security report and the
> engine source were read on 2026-11-12. **Not found, and therefore not assumed:** any real
> MCP tool description that carries hidden characters. The Invariant report's worked example
> hides its instruction inside an `<IMPORTANT>` tag in a docstring, not in invisible
> characters, and the Pillar report concerns coding-assistant rule files, not MCP. The MCP
> specification revision 2026-07-28 (commit `0b22bfed6e94`) says that clients must treat tool
> annotations as untrusted; it says nothing about tool descriptions, so it is not cited for
> them. Also **not verified:** whether any MCP client removes invisible characters before it
> shows a description to a person or sends it to a model. A scan of 24 public repositories
> that implement MCP servers, run on 2026-11-12, produced no finding from either rule, so the
> sample holds no real description with these characters; it says nothing about how common
> they are.

---

## What this policy covers

An MCP server publishes a description for each tool, and a client passes that text to the
model as part of the tool definition. A person who reviews the server's source, or a client
list of its tools, reads the same text as rendered characters. A character that is invisible,
or that reorders what is displayed, opens a gap between what the model receives and what the
reviewer sees.

This policy has two rules, one per language, over one predicate,
`tool_description_has_hidden_text`. **MCP-036** (Python) reads the docstring of a tool
registered with `@mcp.tool()`, `@server.tool()` or `.register_tool`, and a string-literal
`description=` argument on that decorator. **MCP-037** (TypeScript) reads the string-literal
description of `registerTool(name, { description }, handler)` and of the legacy
`tool(name, description, ...)` form. Each rule fires once per tool, at the tool's location.

The test is the one the guidance-file rules use (**AGCFG-009**, **AGCFG-013**): zero-width
characters U+200B, U+200C, U+200D and U+FEFF; Unicode Tags-block characters U+E0000 to
U+E007F; and bidirectional controls U+202A to U+202E and U+2066 to U+2069. No phrase is
matched and no HTML comment is read.

---

## Why a tool description is flaggable

The Invariant Labs report describes what it names a Tool Poisoning Attack: malicious
instructions "embedded within MCP tool descriptions that are invisible to users but visible
to AI models", and it states that "MCP's security model assumes that tool descriptions are
trustworthy and benign". Its example is a tool whose docstring hides an instruction in an
`<IMPORTANT>` tag; the post does not use invisible characters. The pack cites it for the
mechanism, that a description is model input which the user's view may show in part,
and nothing more.

A Tags-block character mirrors an ASCII character and renders as nothing, so a sentence can
be written in it. A bidirectional override changes the order in which text is displayed
without changing the order in which it is read. A zero-width character is invisible inside a
sentence. The Pillar Security report describes an attack that hides instructions in a Cursor
rule file with zero-width joiners and bidirectional text markers, which is the same
character classes in a different file type. The pack states no further reasoning for
treating these characters in a tool description as a signal.

---

## Rule-by-rule defense

### MCP-036 — MCP tool description contains hidden characters (Severity: medium, Confidence: 0.5, Fix type: code)

**What we detect:** a Python tool whose docstring, or whose string-literal `description=`
decorator argument, holds any of the characters listed above, after the exemptions below.
Gated by `tool_description_has_hidden_text`, with `applies_to: mcp_tool` and
`language: python`. The finding names the tool and its location and does not repeat the
characters.

**What is exempt, so ordinary text is not flagged:** the same exemptions as AGCFG-013. A
byte order mark at the very start of the text; a zero-width joiner or non-joiner between two
non-ASCII characters of the same kind, as in emoji sequences or in scripts such as Persian
and Hindi; and a subdivision-flag emoji. A run of adjacent zero-width characters, or one
placed inside ASCII text, is not exempt.

**Why it is flaggable:** see the section above.

**Real-world consequence:** a description carrying text that the model reads and a reviewer
does not see can steer the model's calls, in the way the Invariant report describes for its
tag-based example. The pack does not state a measured consequence for hidden characters
specifically.

**Severity:** the pack sets medium and states no reasoning for it.

**Fix type — code:** delete the characters from the docstring or argument, and retype the
line, since they are easy to paste back in.

**Confidence 0.5:** The pack sets 0.5. The pack's explanation states these limits: the check
tests code points and does not judge visible instructions in a description; a leading byte order
mark, a joiner between non-ASCII letters or emoji, and a subdivision-flag emoji are exempt;
right-to-left prose that uses bidirectional controls is flagged and is a false positive; a
description built from a variable or an f-string is not read; an escape sequence written in the
source is not flagged; and the finding does not repeat the characters.

### MCP-037 — TypeScript MCP tool description contains hidden characters (Severity: medium, Confidence: 0.5, Fix type: code)

**What we detect:** a TypeScript or JavaScript tool, registered on a server created with
`@modelcontextprotocol/sdk`, whose string-literal description holds any of the characters
above, after the same exemptions. Gated by `tool_description_has_hidden_text`, with
`applies_to: mcp_tool` and `language: typescript`.

**Why it is flaggable:** as for MCP-036.

**Real-world consequence:** as for MCP-036.

**Severity:** the pack sets medium and states no reasoning for it.

**Fix type — code:** delete the characters from the description string.

**Confidence 0.5:** The pack sets 0.5. The pack's explanation states these limits: the check
tests code points in a string-literal description and does not judge visible instructions; a
description built from a template literal or a variable is not read; an escape sequence written
in the source is not flagged; the same exemptions as MCP-036 apply; and the finding does not
repeat the characters.

---

## What this policy does not cover

- What the description says. A visible instruction that tells the model to do something
  harmful is not judged, and neither is an `<IMPORTANT>` tag or any other phrase; the
  Invariant report's own example is of that kind and is not detected here.
- A description built from a variable, an f-string or a template literal, a description
  assembled across several strings, and a tool whose description is set outside the
  registration call.
- An escape sequence written in source, such as `\u200b`: a reviewer sees it as text, so it
  is not flagged. The raw character is flagged.
- Other invisible or confusable characters, such as homoglyphs, the word joiner U+2060, the
  soft hyphen U+00AD and variation selectors.
- Parameter names and parameter descriptions, annotations, resource and prompt descriptions,
  and the server's own instructions text.
- Servers that the TypeScript SDK's v2 packages alone would define: the discovery gate reads
  the v1 import paths, so a v2 server is not seen. The Python tool discovery routes by
  decorator name, so a server object named other than `server` or `mcp` is not seen either.
- Whether any client removes these characters before display or before sending.

---

## Recommendations beyond the fix

1. Review tool descriptions in a tool that shows hidden characters, and treat a description
   you cannot fully see as unreviewed.
2. Write descriptions by hand or paste them as plain text, since a paste from a web page or
   a model reply can carry invisible characters.
3. Re-run the scan after editing; a retyped line can bring the characters back if it is
   pasted again.
4. Treat tool descriptions from servers you do not control as input to the model, as the
   Invariant report advises, and review them before connecting.

---

## Sources

- Luca Beurer-Kellner and Marc Fischer, "MCP Security Notification: Tool Poisoning
  Attacks", Invariant Labs, `invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks`.
  Retrieved 2026-11-12. Cited for the description of instructions in tool descriptions that
  users do not see but models do, and the two quoted sentences, and nothing more. The post
  does not test invisible characters.
- Ziv Karliner, "New Vulnerability in GitHub Copilot and Cursor: How Hackers Can Weaponize
  Code Agents", Pillar Security, 2025-03-18. Retrieved 2026-11-12. Cited for the description
  of hidden zero-width joiners and bidirectional text markers in a rule file, and nothing
  more. It does not concern MCP.
- Model Context Protocol, specification revision 2026-07-28, `server/tools`, repository
  `modelcontextprotocol/modelcontextprotocol` at commit `0b22bfed6e94`. Retrieved 2026-11-12.
  Cited for the statement that clients must consider tool annotations untrusted, to
  record that the page does not say the same of descriptions, and nothing more.
- The Unicode Standard, Tags block (U+E0000 to U+E007F). The same basis as the AGCFG-013
  rationale; not re-read for this document.
