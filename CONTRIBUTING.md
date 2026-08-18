# Contributing

OSS -- OopsSec Store is open source. Contributions happen through pull requests.

---

## How to contribute

1. Fork the project on GitHub
2. Create a branch for your changes
3. Follow the guidelines below
4. Open a pull request describing what you changed and why
5. Wait for a review -- maintainers will get to it when they can

Be respectful in reviews, whether you're contributing or reviewing.

---

## Guidelines

- Document new vulnerabilities
- Keep vulnerable code intentionally vulnerable
- Don't introduce real secrets

## What you can work on

New here? Check [good first issues](https://github.com/users/kOaDT/projects/3/views/6).

- New flags
- Walkthroughs and writeups
- E-commerce site development
- Bug fixes
- Documentation
- Issue reports

### Adding a challenge

A challenge is spread over the app, the docs site and the teaching material. Nothing in the app breaks when one of those is forgotten — it reads its totals from the database — so a parity suite guards the rest.

> **Start here.** Add your flag to `prisma/flags.ts`, then run `npm run test:unit`. `tests/unit/challenge-parity.test.ts` fails once for every file you still have to update, and names it. Work through the failures until it is green: that _is_ the checklist.

#### 1. Register the flag

Append an entry to the `flags` array in [`prisma/flags.ts`](prisma/flags.ts):

```typescript
{
  flag: "OSS{y0ur_fl4g}",
  slug: "your-vulnerability",
  cwe: "CWE-89",
  owasp: "A05:2025",
  markdownFile: "your-vulnerability.md",
  walkthroughSlug: "your-vulnerability-writeup",
  category: "INJECTION",
  difficulty: "MEDIUM",
},
```

| Field             | Notes                                                                                                                                   |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `flag`            | `OSS{...}`, unique. Leetspeak is the house style.                                                                                       |
| `slug`            | kebab-case. Becomes `/vulnerabilities/<slug>` and the join key with the roadmap.                                                        |
| `markdownFile`    | File name in `content/vulnerabilities/` (step 4).                                                                                       |
| `walkthroughSlug` | Required. Id of the post in `docs/src/data/blog/` (step 6). Two chained challenges may share one.                                       |
| `category`        | One of the `FlagCategory` values in `prisma/schema.prisma`.                                                                             |
| `difficulty`      | `EASY`, `MEDIUM` or `HARD`.                                                                                                             |
| `cve` `cwe`       | Optional, e.g. `CVE-2025-29927` / `CWE-89`. Rendered as badges linking to NVD and MITRE.                                                |
| `owasp`           | Optional. OWASP Top 10 2025 id (`A05:2025`); legacy 2021 ids such as `A10:2021` are accepted for categories dropped in 2025, like SSRF. |

#### 2. Add three hints

In the `flagHints` map of the same file, keyed by your slug. Level 1 is a vague nudge, level 2 gives direction, level 3 is near-solution. Players unlock them one at a time.

#### 3. Implement the vulnerability

Write the vulnerable code path — API route, page, feature — that hands out the flag. It has to be genuinely exploitable, not simulated. Along the way you may need to:

- seed supporting data (a product, a coupon, an order) in `prisma/seed.ts`;
- add a model to `prisma/schema.prisma`, then run `npm run db:generate && npm run db:push`;
- give players a way in — a link in `app/components/Header.tsx`, `Footer.tsx` or the admin dashboard. A challenge nobody can find is a challenge nobody solves.

Return the flag from the database, never a hardcoded string:

```typescript
const flag = await prisma.flag.findUnique({
  where: { slug: "your-vulnerability" },
});
```

#### 4. Write the in-app reference doc

Add `content/vulnerabilities/<markdownFile>`. This is rendered at `/vulnerabilities/<slug>` once the player finds the flag:

- Overview — what the vulnerability is
- Why it is dangerous
- Vulnerable code (the snippet from this codebase)
- Secure implementation (how to fix it)
- References (OWASP, CWE…)

Do **not** put step-by-step exploitation, payloads, screenshots or the flag value here — the parity suite rejects a flag value in this folder. Those belong in the walkthrough. This page explains the concept and the fix; it does not re-teach the exploit the player just pulled off.

#### 5. Add regression tests

Tests keep the vulnerability exploitable so nobody accidentally patches it:

- `tests/helpers/flags.ts` — add your flag value to the `FLAGS` map (required, even if no test consumes it yet)
- `tests/unit/` — helpers you introduced (hashing, token derivation, filters)
- `tests/api/<slug>.test.ts` — the exploitation scenario against the API
- `cypress/e2e/<slug>.cy.ts` — the full flow through the UI, when the exploit is browser-driven

Assert the **vulnerable** behaviour. A test that asserts the secure behaviour will pass the day someone accidentally fixes the challenge, which defeats the point.

#### 6. Write the walkthrough

The walkthrough lives on the docs site and is where the exploitation belongs: payloads, request examples, screenshots, narrative voice. See [Writing walkthroughs](#writing-walkthroughs) below.

A post has to exist for the docs site to build — an unfinished one can ship as `draft: true`. Its id (the frontmatter `slug` if present, otherwise the file name) must equal the `walkthroughSlug` you set in step 1.

#### 7. Place it on the roadmap

Add the challenge to the right chapter in [`docs/src/data/roadmap.ts`](docs/src/data/roadmap.ts). `slug`, `difficulty`, `category` and `walkthroughSlug` must match the flag exactly; `estimatedMinutes` is `[min, max]`, with a `null` max for open-ended.

Everything downstream is generated from this file — the roadmap page, `/topics`, `challenges.json`, the "Builds on / Next" links. Two things to watch:

- **Inserting in the middle renumbers the curriculum.** Challenge numbers are positional. Re-check every `prerequisites` array, which references those numbers.
- Adding a chapter changes the chapter count quoted in `README.md` and `EDUCATORS.md`.

#### 8. Update the teaching material

- `README.md` — the challenge count in the feature list and in the comparison table
- `EDUCATORS.md` — the count in the intro, the OWASP coverage grid, the challenge catalog table (renumbered if you inserted in the middle), the total estimated time, and the day/week plans in the Syllabus Integration Guide

The parity suite checks the counts and the catalog table row by row; the OWASP grid and the syllabus plans are on you.

#### 9. Special cases

| Situation                             | Also update                                                                                                                                                     |
| ------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| New `FlagCategory`                    | `prisma/schema.prisma`, `lib/types/index.ts`, `lib/format.ts` (`CATEGORY_LABELS`), `app/player-dashboard/PlayerDashboardClient.tsx`, `docs/src/data/roadmap.ts` |
| Acronym in the slug (SSRF, MCP, XXE…) | `TITLE_OVERRIDES` in `lib/format.ts`, otherwise the UI renders `Ssrf`                                                                                           |
| Malicious artifact (payload, package) | Put it under `lab/quarantine/`, declare it in `AGENTS.md`, exclude it from `tsconfig.json`, `eslint.config.mjs` and `.prettierignore`                           |
| New asset directory                   | `Dockerfile` (`mkdir -p`), `.dockerignore`, `.gitignore`                                                                                                        |
| New environment variable              | `.env`, `scripts/setup.sh`, `Dockerfile`, and the `env:` block of `.github/workflows/test.yml` if a test needs it                                               |
| New admin route to gate               | the `matcher` in `middleware.ts`                                                                                                                                |

#### 10. Run the checks

```bash
npm run db:push && npm run db:seed
npm run lint && npm run format:check
npm run test:unit          # parity suite + unit tests
npm run test:api           # needs a running server
npm run test:e2e           # needs a running server
npm run docs:build         # validates walkthroughSlug against the posts
```

### Writing walkthroughs

The [walkthroughs site](https://kOaDT.github.io/oss-oopssec-store) accepts community contributions.

To add one:

1. Fork and clone:
   ```bash
   git clone https://github.com/kOaDT/oss-oopssec-store.git
   cd oss-oopssec-store
   ```
2. Install docs dependencies:
   ```bash
   cd docs
   npm install
   ```
3. Start the dev server:
   ```bash
   npm run dev
   # Or from the root: npm run docs:dev
   ```
4. Go to `docs/src/data/blog/`
5. Create a new markdown file or edit an existing one (e.g. `sql-injection-writeup.md`)
6. Structure your walkthrough roughly like this:
   - Title and metadata (frontmatter)
   - Introduction -- what the vulnerability is
   - Discovery -- how you found it
   - Exploitation -- step-by-step, with screenshots
   - Flag retrieval -- how to grab the flag
   - Remediation (optional) -- how to fix it
7. Put screenshots in `docs/src/assets/images/[vulnerability-name]/`
8. Preview at `http://localhost:4321`
9. Open a pull request

Example frontmatter:

```markdown
---
author: Your Name
pubDatetime: 2026-01-20T10:00:00Z
modDatetime: 2026-01-20T10:00:00Z
title: SQL injection walkthrough
featured: true
draft: false
tags:
  - sql-injection
  - database
  - walkthrough
description: Exploiting the SQL injection vulnerability in OopsSec Store
---
```

Write for someone learning. Explain your reasoning, not just the steps. Include screenshots or code snippets where they help. Test your walkthrough before submitting to make sure the steps actually work.

For more on writing posts with AstroPaper, see the [AstroPaper documentation](https://astro-paper.pages.dev/posts/adding-new-posts-in-astropaper-theme/).

### Joining the Hall of Fame

Captured every flag? Add yourself to `hall-of-fame/data.json` and open a pull
request. Merging it publishes your entry on the `/hall-of-fame` page and builds
your badge — the merged pull request is the whole of the verification, so the
schema is enforced strictly and a malformed entry **fails the docs build on your
pull request**:

```json
{
  "username": "kOaDT",
  "avatarUrl": "https://avatars.githubusercontent.com/u/17499022?v=4",
  "githubUrl": "https://github.com/kOaDT",
  "date": "2026-01-16",
  "country": "France"
}
```

| Field       | Rule                                                                                                                                                                                        |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `username`  | Your GitHub username, as GitHub itself allows it: alphanumerics with single inner hyphens, 39 characters max. It also has to be unique case-insensitively, since it names your badge files. |
| `avatarUrl` | Must be `https` on `avatars.githubusercontent.com` — the docs build fetches it on a runner, so no other host is accepted. Copy it from your GitHub profile picture.                         |
| `githubUrl` | Must be `https://github.com/<you>`.                                                                                                                                                         |
| `date`      | The day you finished, `YYYY-MM-DD`. It is read as UTC and printed on your badge.                                                                                                            |
| `country`   | Optional, free text.                                                                                                                                                                        |

Run `npm run test:unit` to check your entry against the same validation the
build applies.

## Roadmap

Planned features and ideas live in the [Roadmap project](https://github.com/users/kOaDT/projects/3).

Starter tasks are in the [good first issues](https://github.com/users/kOaDT/projects/3/views/6) view.
