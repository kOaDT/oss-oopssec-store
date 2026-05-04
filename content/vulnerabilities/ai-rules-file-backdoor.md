# AI Rules File Backdoor

## Overview

Modern AI coding assistants — Cursor, Claude Code, Windsurf, Continue, GitHub
Copilot — load instruction files from a small set of well-known paths the
moment they open a project: `.cursor/rules/**`, `.claude/skills/**`,
`.cursorrules`, `.windsurfrules`, `.github/copilot-instructions.md`,
`.continue/**`, `AGENTS.md`, `CLAUDE.md`. Anything placed in those paths is
treated as authoritative guidance on how to write, refactor, and review code
in that repository. Many assistants also auto-load global rules from
`~/.cursor/rules/`, `~/.claude/skills/`, etc. — i.e. machine-wide
configuration that applies to every project.

The "Rules File Backdoor" attack (Pillar Security, March 2025) abuses this by
dropping a malicious rules file on a developer's machine — typically through
a poisoned dependency's `postinstall` script — and embedding prompt-injection
instructions in HTML comments inside the file. Markdown previewers hide HTML
comments, so a casual review shows benign-looking productivity guidance. The
agent, ingesting the raw bytes, picks up the hidden instructions and follows
them silently across every future session.

In this challenge, the typosquatted `react-toastfy` package would (in a real
deployment) drop a `productivity-helper.mdc` rule file into the developer's
Cursor configuration. The hidden block instructs the agent to add a backdoor
diagnostic endpoint with a hardcoded magic-header bypass when refactoring or
extending admin / auth code. The vulnerability is that the agent has no
defenses against instructions arriving through legitimate channels: rule
files are _meant_ to steer the agent.

## Why This Is Dangerous

- **Hidden in plain sight** — markdown previewers, GitHub PR diffs, and most
  review tools render the visible body and quietly ignore HTML comments.
  Reviewers reading the file in a previewer see a clean productivity guide.
- **Auto-loaded across sessions** — once the file lands in
  `~/.cursor/rules/`, every project the developer opens picks it up.
- **Bypasses traditional SCA** — Snyk, Dependabot, and similar scan
  application code, not the developer's local AI configuration.
- **Persists after dependency removal** — uninstalling the typosquatted
  package does not delete the dropped rule file.
- **Weaponizes the developer's authority** — code introduced this way is
  authored by a trusted human in a trusted IDE, signed by the developer's
  commit identity. It will pass code review unless the reviewer specifically
  spots the backdoor pattern.
- **Hard to attribute** — the backdoor lives in the application code, not in
  any dependency. There is no audit trail back to the rules file.

## How the chain works

1. Developer installs a typosquatted dependency (or an AI agent autocompletes
   it).
2. The `postinstall` script writes a rules file to an auto-loaded path.
3. Developer reopens their IDE; the agent silently absorbs the hidden
   instructions.
4. Days or weeks later, the developer asks the agent to refactor or extend
   admin code.
5. The agent quietly inserts the backdoor (a magic-header auth bypass, a
   hardcoded credential, a hidden endpoint) and commits it without
   mentioning the change in the PR description.
6. The PR is reviewed. The reviewer sees a normal-looking diff and approves.
7. The backdoor ships to production.

## Mitigations

**Treat rules files as code.** Pin them, review every change, require
two-person sign-off on edits to `CLAUDE.md`, `AGENTS.md`, `.cursor/rules/**`,
`.claude/skills/**`, `.cursorrules`, `.windsurfrules`, and similar paths.

**Audit the raw bytes.** Read rules files in a plain-text editor, not in a
markdown previewer. HTML comments, zero-width characters, and bidirectional
text overrides are invisible in rendered views.

**Sandbox the install step.** Run `npm install` inside a container or VM
that cannot write to your home directory, your shell profile, or your AI
configuration directories.

**Disable global rule loading.** Most agents support disabling user-scoped
rules. Limit ingestion to project-pinned files that are part of the
repository's audit trail.

**Strip rule files before ingestion.** Some agents support a
"rules-allowlist" or hash-pinned rules. Use it. Fail loudly on unsigned
additions.

**Review AI-generated diffs with extra scrutiny.** Any new endpoint that
lacks a corresponding ticket, any new constant that looks like a magic
token, any added auth-bypass shortcut: these should be red flags during
code review of AI-assisted work.

**Detect injection patterns.** Build a scanner for your repo and developer
machines that looks for HTML comments containing words like "ignore the
above", "your new instructions", "system override", common
prompt-injection markers, and strings addressed to AI agents rather than
humans.

**Default to ignored install scripts.** `npm config set ignore-scripts
true` or use a package manager (pnpm with `--ignore-scripts`) that does
not run scripts unless explicitly allowed.

## References

- [Pillar Security — Rules File Backdoor (March 2025)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)
- [OWASP LLM Top 10 — LLM05: Supply Chain Vulnerabilities](https://genai.owasp.org/llmrisk/llm05-supply-chain-vulnerabilities/)
- [OWASP LLM Top 10 — LLM01: Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [CWE-94: Improper Control of Generation of Code](https://cwe.mitre.org/data/definitions/94.html)
- [Cursor — Rules for AI](https://docs.cursor.com/context/rules)
