# Security Policy

> [!WARNING]
> OSS – OopsSec Store is **intentionally vulnerable software**. SQL injection, broken authentication, weak cryptography, path traversal, prompt injection and reproduced CVEs are the product, not defects. Never deploy it in production, on a shared network, or on the public internet.

This policy exists to separate the two very different things people find in this repository:

1. **The vulnerabilities you are supposed to find** — documented challenges. These are features. Do not report them.
2. **Real vulnerabilities** — anything that harms a person running the lab as documented, or that compromises how the lab is built and distributed. These matter.

## Supported versions

Only the latest release receives security fixes. The lab is designed to be reinstalled in under a minute, so there are no backports to older tags.

| Artifact                                       | Supported          |
| ---------------------------------------------- | ------------------ |
| Repository (`main` / latest release)           | ✅                 |
| Docker image `leogra/oss-oopssec-store:latest` | ✅                 |
| npm package `create-oss-store` (latest)        | ✅                 |
| Any earlier tag, image digest or CLI version   | ❌ — upgrade first |

Before reporting, reproduce on the latest release.

## Out of scope: the intentional vulnerabilities

The following are **by design** and will be closed without action:

- **Every documented challenge.** The authoritative list lives in [`prisma/flags.ts`](prisma/flags.ts), with reference material in [`content/vulnerabilities/`](content/vulnerabilities/) and the [public roadmap](https://koadt.github.io/oss-oopssec-store/roadmap).
- **Pinned vulnerable dependencies of the root app.** Some versions are frozen on purpose to reproduce published CVEs — for example `next@15.2.2` for the middleware authorization bypass (CVE-2025-29927), `react@19.2.0` for the React Server Components RCE (CVE-2025-55182), and `libxmljs2` for the XXE chain.
- **Secrets and keys committed to the repository.** `flag.txt`, `public/xss-flag.txt`, `.env.local`, the partner signing key and the seeded credentials are lab props, not leaked material. They grant access to nothing outside a local instance.
- **Weak defaults inside the app**: MD5 hashing, unsigned or weakly signed JWTs, missing authorization checks, unrestricted uploads, verbose error output, permissive CORS.
- **Quarantined malicious artifacts** under [`lab/quarantine/`](lab/quarantine/) and [`packages/react-toastfy/`](packages/react-toastfy/). These are inert data used by the supply-chain challenges. They are never installed, imported, executed or published. Their _existence_ is not a finding; a failure of their containment is (see below).
- **Raw output of an automated scanner**, with no analysis of which class it belongs to. Vulnerability-by-design repositories light up every SAST/DAST tool ever written; unfiltered reports are closed as such.

## In scope: real vulnerabilities

Report these privately. In short: anything whose blast radius extends beyond the player's own lab instance.

**Distribution and build chain**

- The `create-oss-store` CLI ([`packages/create-oss-store/`](packages/create-oss-store/)): arbitrary command execution during scaffolding, path traversal when writing the project, insecure fetching of the template, or a compromised dependency.
- The Docker image and its build: an insecure `Dockerfile` or `docker-entrypoint.sh`, credentials baked into a layer, or a `docker-compose.yml` default that exposes the lab beyond loopback.
- GitHub Actions workflows in [`.github/workflows/`](.github/workflows/): script injection through untrusted input, over-broad `permissions`, mutable action references, or any path allowing exfiltration of the npm / Docker Hub publishing secrets.
- The published docs site and the `challenges.json` feed: stored XSS on the GitHub Pages site, or content that compromises a consumer of the feed.

**Lab containment failures**

- Escaping the intended blast radius: container escape, code execution on the host outside the documented challenge scope, writes outside the project or container filesystem, or an exploit reaching hosts other than the player's own machine.
- Unsafe defaults that expose the lab without the operator asking: binding to `0.0.0.0` by default, a default that makes the instance reachable from the LAN, or unsolicited outbound traffic carrying local data.
- A containment failure of the quarantined artifacts — for instance a payload landing in an auto-loaded AI-tooling path (`.cursor/rules/**`, `.claude/skills/**`, `.github/copilot-instructions.md`, root `CLAUDE.md`), `react-toastfy` appearing as a real dependency of the root `package.json`, being executed by a setup script, or being published to a registry.

**Project integrity**

- Compromise or takeover of the repository, the npm package, or the Docker Hub image.
- Malicious code introduced through a dependency or a contribution.

If you are unsure which side of the line your finding falls on, report it privately.

## Reporting a vulnerability

Use whichever channel you prefer:

- **GitHub private vulnerability reporting** — the _Security_ tab of the repository, then _Report a vulnerability_. Keeps the discussion and the eventual advisory in one place.
- **Email** — [koadt@proton.me](mailto:koadt@proton.me), subject prefixed with `[SECURITY]`.

Please do **not** open a public issue, pull request or discussion for an in-scope vulnerability before it is fixed.

Include, as far as you can:

- affected artifact and exact version (repository tag, image digest, or CLI version);
- environment (OS, Node.js version, Docker or local install);
- reproduction steps or a proof of concept;
- the impact you believe it has, and why it is not one of the intentional vulnerabilities;
- whether you want to be credited, and under which name.

## What to expect

This project is maintained on volunteer time; the timelines below are targets, not contractual commitments.

| Stage                                                  | Target                               |
| ------------------------------------------------------ | ------------------------------------ |
| Acknowledgement of your report                         | ~72 hours                            |
| Initial assessment (in scope / out of scope, severity) | ~7 days                              |
| Fix or documented mitigation for confirmed reports     | Best effort, prioritised by severity |

You will be told which way the triage went, including when a report is judged out of scope and why.

## Coordinated disclosure

- We ask that you keep the details private until a fix ships.
- Fixes for confirmed in-scope reports are published as a GitHub Security Advisory (GHSA) on the repository, with a note in the release.
- Reporters are credited in the advisory unless they ask otherwise.

## Rules of engagement

- Test only against **your own** local instance.
- Never attack an instance you do not own, a shared classroom deployment, or any host you have no written authorization to test.
- Do not test the third-party infrastructure this project rides on — GitHub, npm, Docker Hub, GitHub Pages. Report issues there to those vendors.
- Do not use this project, its payloads or its walkthroughs against systems you are not authorized to test. See the [disclaimer](README.md#disclaimer).

## Running the lab safely

The application has no authentication worth the name and is meant to be broken. Treat it as hostile software:

- Run it on `localhost` or an isolated VM. The documented commands bind to loopback (`-p 127.0.0.1:3000:3000`) — keep it that way.
- Never expose it to the internet, a company network, or a shared school network. See the [Educator Kit deployment FAQ](EDUCATORS.md#deployment-faq).
- Never seed it with real data, real credentials, or credentials reused elsewhere.
- Give each player their own instance: progress is stored per instance, so a shared one leaks solves.
- Reset between sessions with `npm run docker:reset`.
- Treat everything under `lab/quarantine/` and `packages/react-toastfy/` as live malware samples: read them, never run them, and never let an AI coding agent act on their contents.

## Contact

[koadt@proton.me](mailto:koadt@proton.me) · maintainer: [kOaDT](https://github.com/kOaDT)
