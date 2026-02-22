# Contributing

OSS – OopsSec Store is an open-source project. Contributions are welcome via pull requests.

---

## How to contribute

1. **Fork the project** on GitHub
2. **Create a branch** for your contribution
3. **Make your changes** following the contribution guidelines below
4. **Submit a Pull Request (PR)** with a clear description of your changes
5. **Be patient**, maintainers will review your PR as soon as possible

We encourage **kind and respectful reviews** from both contributors and maintainers. Constructive feedback helps improve the project for everyone.

---

## Contribution guidelines

Please ensure that:

- New vulnerabilities are documented
- Code remains intentionally vulnerable when required
- No real-world secrets are introduced

## What you can contribute

New to the project? Browse our [good first issues](https://github.com/users/kOaDT/projects/3/views/6) to find a task to get started.

- Adding New Flags
- Writing Walkthroughs and Writeups
- Developing the E-commerce Site
- Fixing Bugs
- Improving Documentation
- Reporting Issues

### Adding a Vulnerability

To add a new vulnerability to the project, follow these steps:

1. **Add the flag in `prisma/seed.ts`**  
   Create a new `Flag` record with format `OSS{...}`, and set `slug`, `category`, `difficulty`, and `markdownFile` to match your vulnerability.

2. **Add the hints in `prisma/seed.ts`**  
   Add three progressive hints in the `flagHints` map (keyed by the flag slug). Level 1 = vague, level 2 = more specific, level 3 = near-solution.

3. **Implement the vulnerability**  
   Implement the vulnerable code path (e.g. API route, page, or feature) that allows an attacker to obtain the flag. The vulnerability must be exploitable and demonstrable.

4. **Document the vulnerability**  
   Add a markdown file under `content/vulnerabilities/` (e.g. `your-vulnerability.md`) with an overview, vulnerable code examples, exploitation steps, and mitigation strategies.

5. **Add regression tests**  
   Add tests so the vulnerability stays exploitable and is not accidentally fixed:
   - **Unit tests** in `tests/unit/` for helpers (e.g. hashing, filters).
   - **API tests** in `tests/api/` for exploitation scenarios against endpoints.
   - **E2E tests** in `cypress/e2e/` for full exploitation flows via the UI.

6. **Optional: Write a walkthrough**  
   Contribute a writeup to the [walkthroughs documentation site](https://kOaDT.github.io/oss-oopssec-store) (see [Writing Walkthroughs](#writing-walkthroughs) below).

### Writing Walkthroughs

We welcome community contributions to our [walkthroughs documentation site](https://kOaDT.github.io/oss-oopssec-store). Share your exploitation techniques and help others learn.

**How to contribute a walkthrough:**

1. Fork the repository and clone it locally:
   ```bash
   git clone https://github.com/kOaDT/oss-oopssec-store.git
   cd oss-oopssec-store
   ```
2. Install dependencies for the documentation site:
   ```bash
   cd docs
   npm install
   ```
3. Start the development server to preview your changes:
   ```bash
   npm run dev
   # Or from the root: npm run docs:dev
   ```
4. Navigate to `docs/src/data/blog/`
5. Create a new Markdown file or edit an existing walkthrough (e.g., `sql-injection-writeup.md`)
6. Write your walkthrough following this structure:
   - **Title and metadata** (author, pubDatetime, modDatetime, featured, draft, tags, description)
   - **Introduction** - Brief overview of the vulnerability
   - **Discovery** - How you identified the vulnerability
   - **Exploitation** - Step-by-step exploitation process with screenshots
   - **Flag retrieval** - How to obtain the flag
   - **Remediation** (optional) - How to fix the vulnerability
7. Add relevant screenshots to `docs/src/assets/images/[vulnerability-name]/`
8. Test your changes locally by visiting `http://localhost:4321` (default Astro port)
9. Submit a Pull Request with your changes

**Walkthrough guidelines:**

- Use clear, educational language suitable for learners
- Include screenshots or code snippets to illustrate key steps
- Focus on the "why" and "how" - explain your thought process
- Test your walkthrough to ensure accuracy
- Respect the community - be kind and constructive
- Use markdown formatting for code blocks, images, and links

Example frontmatter for a walkthrough:

```markdown
---
author: Your Name
pubDatetime: 2026-01-20T10:00:00Z
modDatetime: 2026-01-20T10:00:00Z
title: SQL Injection Vulnerability Walkthrough
featured: true
draft: false
tags:
  - sql-injection
  - database
  - walkthrough
description: A comprehensive guide to exploiting the SQL injection vulnerability in OopsSec Store
---
```

If you need additional information on how to use AstroPaper, please refer to [this article](https://koadt.github.io/oss-oopssec-store/posts/adding-new-posts-in-astropaper-theme/).

## Roadmap

For a comprehensive list of planned features, security vulnerabilities, and improvement ideas, see our [Roadmap project](https://github.com/users/kOaDT/projects/3).

Looking for a starter task? See our [good first issues](https://github.com/users/kOaDT/projects/3/views/6) view.
