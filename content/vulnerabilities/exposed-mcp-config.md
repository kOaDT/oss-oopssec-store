# Exposed MCP Config

## Overview

Claude Code reads the servers an AI agent may launch from a project config file, `.mcp.json` at the root of the checkout. VS Code reads that portable file too, next to its own `.vscode/mcp.json`. A local (stdio) server receives its credentials through the `env` block of that file, and popular setup guides often tell you to paste the raw token there. The file lives next to the code, so it travels with every copy of the checkout.

In this challenge, the storefront was deployed from a developer's checkout, `.mcp.json` included. The file hardcodes a Hugging Face user access token, shared by two MCP servers. One of them reaches the company's Hub mirror, and the token can read a private dataset of customer support conversations.

## Why This Is Dangerous

- **Common, and already scanned for**: GitGuardian counted 24,008 unique secrets in MCP-related configuration files on public GitHub in 2025, 2,117 of them still valid. Public scanner templates probe `/.mcp.json` and `/mcp.json` on websites.
- **One file, every credential the agent uses**: an MCP config gathers the tokens of every service an agent talks to (model hubs, code hosting, databases, search APIs) in a single readable file.
- **A token describes itself**: its prefix names the issuer, and the issuer's identity endpoint returns the owner, their organizations and the token's scope. The finder does not need to guess what it opens.
- **A model hub token reaches data, not just models**: private datasets often hold training data, here support transcripts with customer names, emails, phone numbers and addresses. A token with write access to a model repository also reaches every system that pulls from it.
- **Fine-grained is not harmless**: limiting a token to one dataset narrows the blast radius. Whatever that dataset holds is still exposed.

## Vulnerable Code

The config pastes the token in clear:

```json
{
  "mcpServers": {
    "support-evals": {
      "command": "uv",
      "args": ["run", "--directory", "tools/support-evals", "server.py"],
      "env": {
        "HF_ENDPOINT": "https://<hub-mirror>",
        "HF_TOKEN": "hf_..."
      }
    }
  }
}
```

And the deployment copies the checkout, dotfiles included, into a web root that serves static files:

```bash
rsync -az ./ deploy@web-01:/var/www/storefront/
```

These snippets belong to the scenario, not to this repository. OopsSec Store runs on Next.js: a route handler serves the config at `/.mcp.json`, and another plays the part of the Hub mirror, answering like the Hugging Face Hub API. The token is derived at runtime and never written in the sources.

## Secure Implementation

**Keep the token out of the file.** Claude Code expands environment variables in `.mcp.json`, in the `command`, `args`, `env`, `url` and `headers` values:

```json
{
  "mcpServers": {
    "support-evals": {
      "command": "uv",
      "args": ["run", "--directory", "tools/support-evals", "server.py"],
      "env": {
        "HF_ENDPOINT": "${HF_ENDPOINT}",
        "HF_TOKEN": "${HF_TOKEN}"
      }
    }
  }
}
```

VS Code's portable `.mcp.json` takes the same `${HF_TOKEN}` references. In its own `.vscode/mcp.json`, declare the token as an input with `password: true` and reference it as `${input:hf-token}`: VS Code prompts for it once and stores it securely.

**Never deploy a working copy.** Ship a build artifact from CI. If you must sync a directory, exclude agent and editor configs along with version control and environment files, and block dotfiles at the reverse proxy:

```bash
rsync -az --exclude='.git' --exclude='.mcp.json' --exclude='.vscode' \
  --exclude='.cursor' --exclude='.claude' --exclude='.env*' \
  ./ deploy@web-01:/var/www/storefront/
```

**Give each tool its own minimal token.** Hugging Face recommends one access token per app or usage, and fine-grained tokens in production. Scope it to the repositories the tool needs, read-only unless it pushes.

**Revoke on discovery.** The owner deletes or refreshes the token from their Access Tokens settings. Anyone who finds somebody else's Hugging Face token can invalidate it with `POST /api/credentials/revoke`, without any rights on the account: the token stops working everywhere and the owner is notified by email. Rotation is the fix; deleting the file afterwards does not un-leak the token.

**Scan for secrets before they ship.** gitleaks has a rule for Hugging Face access tokens, and GitHub secret scanning detects them with push protection. Run the scanner over the files you deploy, not only over what you commit.

**Scrub training data.** A private dataset is one leaked token away from public. Remove personal data before it reaches a dataset, not after.

## References

- [CWE-538: Insertion of Sensitive Information into Externally-Accessible File or Directory](https://cwe.mitre.org/data/definitions/538.html)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [OWASP Top 10 — A02:2025 Security Misconfiguration](https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/)
- [Hugging Face — User access tokens](https://huggingface.co/docs/hub/en/security-tokens)
- [Claude Code — MCP](https://code.claude.com/docs/en/mcp)
- [VS Code — MCP configuration reference](https://code.visualstudio.com/docs/agents/reference/mcp-configuration)
- [GitGuardian — The State of Secrets Sprawl 2026](https://blog.gitguardian.com/the-state-of-secrets-sprawl-2026/)
- [GitHub — Supported secret scanning patterns](https://docs.github.com/en/code-security/reference/secret-security/supported-secret-scanning-patterns)
- [gitleaks](https://github.com/gitleaks/gitleaks)
