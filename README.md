<div align="center">
<h1>OSS - OopsSec Store</h1>
</div>

<div>

```
   ____  ____ ____     ____                  ____            ____  _
  / __ \/ __// __/    / __ \ ___   ___  ___ / __/ ___  ____ / __/ / /_ ___   ____ ___
 / /_/ /\ \ _\ \     / /_/ // _ \ / _ \(_-<_\ \  / -_)/ __/_\ \  / __// _ \ / __// -_)
 \____/___//___/     \____/ \___// .__/___/___/  \__/ \__//___/  \__/ \___//_/   \__/
                                /_/
  $ npx create-oss-store
  $ cd my-oss-store && npm start

  → Open http://localhost:3000 and start hunting flags
```

</div>

<p align="center">
  <b>An intentionally vulnerable e-commerce app for learning web security.</b>
</p>

<p align="center">
  <b>Master real-world attack vectors through a realistic Capture The Flag platform. Hunt for flags, exploit vulnerabilities, and level up your security skills.</b>
</p>

<p align="center">
  <a href="https://github.com/kOaDT/oss-oopssec-store/blob/main/CONTRIBUTING.md">Contributing</a> |
  <a href="https://github.com/users/kOaDT/projects/3">Roadmap</a> |
  <a href="https://github.com/users/kOaDT/projects/3/views/6">Good first issues</a> |
  <a href="https://kOaDT.github.io/oss-oopssec-store">Walkthroughs</a>
</p>

<div align="center">

[![GitHub license](https://img.shields.io/github/license/kOaDT/oss-oopssec-store?style=flat-square)](https://github.com/kOaDT/oss-oopssec-store/blob/main/LICENSE)
[![npm version](https://img.shields.io/npm/v/create-oss-store?style=flat-square)](https://www.npmjs.com/package/create-oss-store)
[![npm downloads](https://img.shields.io/npm/dm/create-oss-store?style=flat-square)](https://www.npmjs.com/package/create-oss-store)
<br>
[![GitHub issues](https://img.shields.io/github/issues/kOaDT/oss-oopssec-store?style=flat-square)](https://github.com/kOaDT/oss-oopssec-store/issues)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square)](https://github.com/kOaDT/oss-oopssec-store/pulls)
[![Good first issues](https://img.shields.io/badge/Good_first-issues-7057ff?style=flat-square)](https://github.com/users/kOaDT/projects/3/views/6)
![Intentionally Vulnerable](https://img.shields.io/badge/⚠️_Intentionally-Vulnerable-red?style=flat-square)
<br>
[![GitHub stars](https://img.shields.io/github/stars/kOaDT/oss-oopssec-store?style=social)](https://github.com/kOaDT/oss-oopssec-store/stargazers) [![GitHub forks](https://img.shields.io/github/forks/kOaDT/oss-oopssec-store?style=social)](https://github.com/kOaDT/oss-oopssec-store/network)

</div>

---

## Table of contents

- [Features](#features)
- [Installation](#installation)
  - [Quick start (npm)](#quick-start)
  - [Docker](#docker)
- [Hall of fame](#hall-of-fame)
- [Project structure](#project-structure)
- [Recent activity](#recent-activity)
- [Testing](#testing)
- [Disclaimer](#disclaimer)
- [Contributing](#contributing)
- [Top contributors](#top-contributors)

---

OSS – OopsSec Store is a fake online store full of security vulnerabilities, on purpose. It's built with Next.js, React, and Prisma, and it covers the usual suspects: OWASP Top 10, API flaws, frontend attack vectors.

Each vulnerability hides a flag. Find the bug, exploit it, grab the flag. Walkthroughs are included if you get stuck.

> [!WARNING]
> This application contains intentional security flaws and must never be deployed in a production environment.

## Features

- Intentionally vulnerable e-commerce app (XSS, CSRF, IDOR, JWT attacks, path traversal, SQL injection, and more)
- Built with Next.js, React, Prisma, and SQLite
- REST API with documented attack vectors
- CTF challenges with hidden flags
- Vulnerability documentation and community walkthroughs for each challenge
- Automated tests that verify exploits still work (PRs that accidentally fix a vuln will fail CI)

## Installation

### Quick start

```bash
npx create-oss-store my-ctf-lab
cd my-ctf-lab
npm start
```

Then open http://localhost:3000 in your browser.

### Manual setup

Clone the repo and run the setup script:

```bash
git clone https://github.com/kOaDT/oss-oopssec-store.git
cd oss-oopssec-store
npm run setup
```

This creates the `.env` file, installs dependencies, sets up the SQLite database, seeds it with CTF flags, and starts the app on port 3000.

### Docker

No Node.js required. Just [Docker](https://docs.docker.com/get-docker/):

```bash
git clone https://github.com/kOaDT/oss-oopssec-store.git
cd oss-oopssec-store
docker compose up -d
```

Or using the npm helper scripts:

```bash
npm run docker:up       # Start in background (builds image on first run)
npm run docker:logs     # Follow container logs
npm run docker:down     # Stop the container
npm run docker:reset    # Wipe data and restart fresh
```

The database initializes on first start. Data persists across restarts via Docker named volumes. To reset everything (flag progress, users, uploads), run `npm run docker:reset`.

### Hall of fame

Found all the flags? Open a pull request to join the [Hall of Fame](hall-of-fame/data.json). Add your entry to `hall-of-fame/data.json` and your profile will show up on the `/hall-of-fame` page in the app.

## Project structure

<div align="center">

[![Structure](https://images.repography.com/103508692/kOaDT/oss-oopssec-store/structure/Q7MububoYUVlm99MQWYW12szb_gGlehkuutaTn9WlA4/xqocpGlYz1v1FH126K5mqp7WjOcy1VH9pbA-EuINusA_table.svg)](https://github.com/kOaDT/oss-oopssec-store)

</div>

| Folder                     | Description                                                    |
| -------------------------- | -------------------------------------------------------------- |
| `app/`                     | Next.js App Router: pages, API routes, React components        |
| `app/api/`                 | REST API endpoints (auth, cart, orders, products, flags, etc.) |
| `app/components/`          | React UI components (Header, Footer, ProductCard, etc.)        |
| `app/vulnerabilities/`     | Pages documenting each vulnerability                           |
| `content/vulnerabilities/` | Markdown descriptions of vulnerabilities and attack vectors    |
| `lib/`                     | Shared utilities: DB client, auth, API helpers, types          |
| `prisma/`                  | Database schema, migrations, and seed script with CTF flags    |
| `public/`                  | Static assets and exploit payloads (e.g., CSRF demo)           |
| `hooks/`                   | Custom React hooks (authentication, etc.)                      |
| `scripts/`                 | Setup and automation scripts                                   |
| `docs/`                    | Static docs site with community walkthroughs                   |
| `hall-of-fame/`            | Player profiles for those who found all flags                  |
| `packages/`                | NPM package `create-oss-store` for scaffolding                 |
| `tests/`                   | Jest unit and API tests that validate exploits                 |
| `cypress/`                 | E2E tests for full exploitation workflows                      |

## Recent activity [![Time period](https://images.repography.com/103508692/kOaDT/oss-oopssec-store/recent-activity/Q7MububoYUVlm99MQWYW12szb_gGlehkuutaTn9WlA4/8o02KXC0HvWi_KfBHD6iD-qSBHSu0s9Y_rns1fvWSjg_badge.svg)](https://repography.com)

<div align="center">

[![Timeline graph](https://images.repography.com/103508692/kOaDT/oss-oopssec-store/recent-activity/Q7MububoYUVlm99MQWYW12szb_gGlehkuutaTn9WlA4/8o02KXC0HvWi_KfBHD6iD-qSBHSu0s9Y_rns1fvWSjg_timeline.svg)](https://github.com/kOaDT/oss-oopssec-store/commits)
[![Trending topics](https://images.repography.com/103508692/kOaDT/oss-oopssec-store/recent-activity/Q7MububoYUVlm99MQWYW12szb_gGlehkuutaTn9WlA4/8o02KXC0HvWi_KfBHD6iD-qSBHSu0s9Y_rns1fvWSjg_words.svg)](https://github.com/kOaDT/oss-oopssec-store/commits)

[![Issue status graph](https://images.repography.com/103508692/kOaDT/oss-oopssec-store/recent-activity/Q7MububoYUVlm99MQWYW12szb_gGlehkuutaTn9WlA4/8o02KXC0HvWi_KfBHD6iD-qSBHSu0s9Y_rns1fvWSjg_issues.svg)](https://github.com/kOaDT/oss-oopssec-store/issues)
[![Pull request status graph](https://images.repography.com/103508692/kOaDT/oss-oopssec-store/recent-activity/Q7MububoYUVlm99MQWYW12szb_gGlehkuutaTn9WlA4/8o02KXC0HvWi_KfBHD6iD-qSBHSu0s9Y_rns1fvWSjg_prs.svg)](https://github.com/kOaDT/oss-oopssec-store/pulls)

</div>

## Testing

The project includes security regression tests that make sure all exploit chains and flags still work. These tests deliberately validate insecure behavior. They run on every PR, so if you accidentally patch a vulnerability, CI will catch it.

### Running tests

```bash
# Unit tests (utility functions: MD5 hashing, JWT, input filters)
npm run test:unit

# API exploitation tests (requires a running server)
npm run test:api

# E2E exploitation tests (requires a running server)
npm run test:e2e

# Open Cypress interactive mode
npm run test:e2e:open

# All tests
npm run test:ci
```

## Disclaimer

> [!CAUTION]
> This project is for educational and authorized security testing only.
> It contains intentional vulnerabilities and insecure configurations. The authors are not responsible for any misuse, damage, or unauthorized access. Use it in isolated environments.

## Contributing

OSS – OopsSec Store is MIT-licensed. Contributions are welcome.

Ways to contribute:

- Add new security challenges
- Write or improve walkthroughs
- Extend the application
- Report and fix bugs
- Improve documentation

Check the [Roadmap](https://github.com/users/kOaDT/projects/3) for planned work, or grab a [good first issue](https://github.com/users/kOaDT/projects/3/views/6).

Found all the flags? Share your walkthroughs on the [docs site](https://kOaDT.github.io/oss-oopssec-store).

For bugs or suggestions, open a [GitHub Issue](https://github.com/kOaDT/oss-oopssec-store/issues). See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## [![Repography logo](https://images.repography.com/logo.svg)](https://repography.com) / Top contributors

<div align="center">

[![Top contributors](https://images.repography.com/103508692/kOaDT/oss-oopssec-store/top-contributors/Q7MububoYUVlm99MQWYW12szb_gGlehkuutaTn9WlA4/8o02KXC0HvWi_KfBHD6iD-qSBHSu0s9Y_rns1fvWSjg_table.svg)](https://github.com/kOaDT/oss-oopssec-store/graphs/contributors)

</div>

---

<div align="center">

Author: [kOaDT](https://github.com/kOaDT)  
Project: [OopsSec Store](https://github.com/kOaDT/oss-oopssec-store)  
Contact: koadt@proton.me

License: [MIT](https://github.com/kOaDT/oss-oopssec-store/blob/main/LICENSE)

Do not remove or modify the LICENSE file in your fork.

</div>
