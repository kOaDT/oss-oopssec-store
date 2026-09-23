---
layout: ../layouts/AboutLayout.astro
title: "About - OopsSec Store"
---

**Security training for the apps you actually ship.**

OopsSec Store is an open-source, deliberately vulnerable e-commerce app built on **Next.js, React, TypeScript and Prisma**. It holds 36 challenges across web, API, authentication, business logic, cryptography, supply chain, AI agents and MCP. Find the bugs, exploit them, and understand why they work.

This site hosts the walkthroughs: one per challenge, from vulnerability to exploit to fix.

## Quick start

```bash
# With Node.js
npx create-oss-store my-ctf-lab && cd my-ctf-lab && npm start

# With Docker
docker run -p 127.0.0.1:3000:3000 leogra/oss-oopssec-store
```

Then open [http://localhost:3000](http://localhost:3000) and start hacking.

## Getting started

1. **Start the lab** with one of the commands above. The store comes up on `localhost:3000`.
2. **Go after challenge #1**, the public env variable leak: a payment secret that Next.js bakes into the client bundle. Easy, 15–20 minutes, nothing but your browser devtools.
3. **Stuck? Read the walkthrough.** The first one is [Reading Secrets From the Browser: The NEXT_PUBLIC\_ Trap in Next.js](/oss-oopssec-store/posts/next-public-env-variable-leak/).
4. **Validate the flag.** Paste `OSS{...}` into the flag checker, the floating widget on every page. Your player dashboard tracks what is left.
5. **Pick the next one.** The [roadmap](/oss-oopssec-store/roadmap) orders every challenge across chapters, with difficulty, time estimate and prerequisites.

New to offensive security? The [TryHackMe room](https://tryhackme.com/jr/oopssecstorethesummeraudit), _The Summer Audit_, wraps the first flags in a guided narrative across 8 tasks and 7 flags.

## Why OopsSec Store?

Modern frameworks change where security vulnerabilities appear and how they should be fixed. OopsSec Store puts the classic vulnerability classes (XSS, CSRF, IDOR, JWT attacks, path traversal, SQL injection and more) into a stack many developers use today.

Server-rendered components, middleware and ORMs introduce different trust boundaries and failure modes. Several challenges also reproduce published CVEs against this stack.

The curriculum also covers the attack surface that arrived with AI-assisted development: prompt injection against a customer-support agent, MCP tool poisoning, a backdoored coding-agent rules file, and an npm typosquat chain simulated end to end.

## Features

- 36 CTF challenges across 11 chapters, laid out as a structured [learning roadmap](/oss-oopssec-store/roadmap)
- A walkthrough and an in-app vulnerability reference for each challenge
- A player dashboard tracking progress by difficulty and category
- A Hall of Fame for players who capture every flag, with a shareable badge
- Automated tests that verify exploits still work: a PR that accidentally fixes a vulnerability fails CI

## Resources

- [GitHub Repository](https://github.com/kOaDT/oss-oopssec-store)
- [npm Package](https://www.npmjs.com/package/create-oss-store)
- [Docker Image](https://hub.docker.com/r/leogra/oss-oopssec-store)
- [OWASP Vulnerable Web Applications Directory](https://vwad.owasp.org/app/oopssec-store/)
- [TryHackMe room](https://tryhackme.com/jr/oopssecstorethesummeraudit): _The Summer Audit_
- [Educator Kit](https://github.com/kOaDT/oss-oopssec-store/blob/main/EDUCATORS.md): OWASP coverage grids, syllabus templates, deployment FAQ
- [Challenge feed (JSON)](https://koadt.github.io/oss-oopssec-store/challenges.json): the curriculum in machine-readable form
- [Discussions](https://github.com/kOaDT/oss-oopssec-store/discussions): questions, solves and challenge ideas

## Disclaimer

OopsSec Store is for educational and authorized security testing only. It contains intentional vulnerabilities and insecure configurations, and must never be deployed in a production environment. Use it in isolated environments.

## Contributing

OSS – OopsSec Store is MIT-licensed. Contributions are welcome: new challenges, walkthroughs, app extensions, bug fixes and documentation.

Grab a [good first issue](https://github.com/users/kOaDT/projects/3/views/6), or read the [Contributing Guide](https://github.com/kOaDT/oss-oopssec-store/blob/main/CONTRIBUTING.md). For bugs in the lab itself, open a [GitHub Issue](https://github.com/kOaDT/oss-oopssec-store/issues).
