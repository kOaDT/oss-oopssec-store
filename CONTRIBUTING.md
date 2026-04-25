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

### Adding a vulnerability

1. **Add the flag in `prisma/seed.ts`**
   Create a `Flag` record with format `OSS{...}`. Set `slug`, `category`, `difficulty`, and `markdownFile` to match. Set `walkthroughSlug` if a walkthrough exists on the docs site (see step 6).

2. **Add hints in `prisma/seed.ts`**
   Add three progressive hints in the `flagHints` map, keyed by slug. Level 1 is vague, level 2 more specific, level 3 near-solution.

3. **Implement the vulnerability**
   Write the vulnerable code path (API route, page, feature) that lets an attacker get the flag. It needs to be actually exploitable.

4. **Document it (reference doc)**
   Add a markdown file under `content/vulnerabilities/` (e.g. `your-vulnerability.md`). This is the **in-app reference** rendered at `/vulnerabilities/<slug>` after a player finds the flag. It should focus on:
   - Overview — what the vulnerability is
   - Why it is dangerous
   - Vulnerable code (the snippet from the codebase)
   - Secure implementation (how to fix it)
   - References (OWASP, CWE, etc.)

   Do **not** include step-by-step exploitation, payloads, screenshots, or the flag value here. Those belong in the walkthrough (step 6). The in-app doc is meant to explain the concept and the fix, not to re-teach the exploit the player just executed.

5. **Add regression tests**
   Tests keep the vulnerability exploitable so nobody accidentally patches it:
   - Unit tests in `tests/unit/` for helpers (hashing, filters, etc.)
   - API tests in `tests/api/` for exploitation scenarios
   - E2E tests in `cypress/e2e/` for full exploitation flows through the UI

6. **Optional: write a walkthrough (the exploit playbook)**
   The walkthrough lives on the docs site (`docs/src/data/blog/`) and is where the step-by-step exploitation belongs: payloads, request examples, screenshots, narrative voice. See [Writing walkthroughs](#writing-walkthroughs) below. If you add one, set `walkthroughSlug` on the flag in `prisma/seed.ts` so the in-app reference page links to it.

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

For more on using AstroPaper, see [this article](https://koadt.github.io/oss-oopssec-store/posts/adding-new-posts-in-astropaper-theme/).

## Roadmap

Planned features and ideas live in the [Roadmap project](https://github.com/users/kOaDT/projects/3).

Starter tasks are in the [good first issues](https://github.com/users/kOaDT/projects/3/views/6) view.
