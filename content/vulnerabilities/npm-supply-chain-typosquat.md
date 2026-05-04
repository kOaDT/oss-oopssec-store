# npm Supply Chain Typosquatting

## Overview

Typosquatting on the npm registry is the practice of publishing a package whose
name is a near-miss of a popular dependency — `react-toastfy` for
`react-toastify`, `lodahs` for `lodash`, `crossenv` for `cross-env`. A
distracted developer (or an AI agent suggesting an autocomplete) installs the
wrong name, and the malicious package's `postinstall` script runs with full
write access to the developer's machine on the next `npm install`.

It is the entry vector behind incidents such as `event-stream` (2018),
`ua-parser-js` (2021), `colors.js` / `faker.js` (2022), and the npm
"Shai-Hulud" worm (2025). The packages look plausible: README tone matches
the legitimate one, the JSON metadata is sensible, and `index.js` exports
something that resembles the real API. The malicious payload is in
`postinstall`, not in the public surface.

## Why This Is Dangerous

- **Silent execution at install time** — `postinstall` runs with the user's
  full permissions, before any code review of the dependency happens.
- **No code-path required** — the attacker does not need their package to be
  imported or used at runtime. The mere act of installing it is enough.
- **Hard to detect after the fact** — the dropped artifact (a binary, a shell
  hook, an auto-loaded AI rules file) lives outside the project tree.
- **Compounds with AI tooling** — modern developer machines auto-load files
  from `~/.cursor/rules/`, `~/.claude/skills/`, `.cursorrules`,
  `.windsurfrules`, `.continue/`, `.github/copilot-instructions.md`. A
  malicious postinstall that drops a rules file there steers the agent
  silently for every future session.
- **Pivots beyond the developer** — once the agent is poisoned, any code it
  generates can carry a backdoor into production.

## Mitigations

**Block install scripts by default.** Use `npm install --ignore-scripts` and
opt in selectively. Better: configure `ignore-scripts=true` in `.npmrc` and
audit which packages need scripts.

**Pin and lock.** Commit `package-lock.json` (or `pnpm-lock.yaml`,
`yarn.lock`). Refuse to update lockfiles in PRs that don't justify the
dependency change in the description.

**Verify package integrity.** `npm audit signatures` validates registry
signatures on installed packages. Fails fast on tampered tarballs.

**Use scoped registries.** Mirror the public registry through an internal
proxy (Verdaccio, Artifactory, Nexus, JFrog) that allowlists known-good
versions and quarantines new releases for review.

**Run SCA on every PR.** Tools like Socket, Snyk, GitHub Dependabot, and
OSSF Scorecard inspect new dependencies for typosquatting heuristics,
missing maintainers, recently transferred ownership, and suspicious
postinstall hooks.

**Treat dependency additions like code review.** A new package in a PR
deserves the same scrutiny as a new file. Read the source, check the
maintainers, look at the install scripts.

**Sandbox `npm install`.** Run installs in a container or VM with no access
to the developer's home directory or AI tooling paths. Some teams ship a
pre-configured devcontainer that isolates `~/.cursor/`, `~/.claude/`,
`~/.config/` from the install environment.

**Review every AI rules / skill file.** Treat `.cursor/rules/**`,
`.claude/skills/**`, `.cursorrules`, `.windsurfrules`, and similar paths as
executable code. A line in there steers your assistant the same way a
system prompt does.

## References

- [OWASP Top 10 2025 — A03 Software Supply Chain Failures](https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/)
- [CWE-829: Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)
- [CWE-506: Embedded Malicious Code](https://cwe.mitre.org/data/definitions/506.html)
- [Pillar Security — Rules File Backdoor (March 2025)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)
- [OWASP LLM Top 10 — LLM05: Supply Chain Vulnerabilities](https://genai.owasp.org/llmrisk/llm05-supply-chain-vulnerabilities/)
- [npm — `--ignore-scripts`](https://docs.npmjs.com/cli/v10/commands/npm-install#ignore-scripts)
- [Socket — typosquatting research](https://socket.dev/blog)
