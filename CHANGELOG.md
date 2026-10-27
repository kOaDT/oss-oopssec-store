# Changelog

All notable changes to OopsSec Store are documented here. This changelog follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and links to the official GitHub release notes for full details.

Entries are summarized from the [GitHub release notes](https://github.com/kOaDT/oss-oopssec-store/releases) at each release.

## [v2.23.0] - 2026-10-27

[Release notes](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.23.0)

### Added

- The Docker image now covers `linux/amd64` and `linux/arm64`, so ARM64 machines run it natively via `docker pull leogra/oss-oopssec-store`.
- A new `CHANGELOG.md` in Keep a Changelog format summarizes every release from its GitHub release notes.

### Changed

- The breach notice on the News page now ends with a nod to how the store hashes passwords.
- Pull request CI now builds and smoke-tests the Docker image on amd64 and arm64, loading native modules `better-sqlite3` and `libxmljs2`.
- Docker images are now published through `docker/github-builder`; manual runs push a throwaway `test-<run id>` tag, never `latest`.
- The Dockerfile now excludes `docs/`, `tests/`, `cypress/`, `.cursor/`, `.husky/` and the CLI package, since BuildKit ignores `.dockerignore` for Git contexts.
- Docs site, `create-oss-store` CLI and CI dependencies are updated, including majors `eslint-plugin-astro` 3.1.0 and `chalk` 6.0.0; app dependencies are unchanged.

### Fixed

- The "Add" button and cart icon on product cards now add to cart, sending signed-out visitors to the login page.
- On the SIEM monitoring login, the Username and Password labels are now tied to their inputs.

## [v2.22.0] - 2026-10-07

[Release notes](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.22.0)

### Added

- New Community Resources section on the Hall of Fame page lists community courses, talks, videos and articles from `hall-of-fame/community-resources.json`.

### Changed

- A multi-stage build shrinks the Docker image, which no longer ships dev tooling such as Jest, ESLint or Cypress.
- Docker startup fails on a missing package instead of downloading it, and `tsx` and `dotenv` are now runtime dependencies.
- The About page on the docs site now matches the README pitch.
- A new CI smoke test runs the Docker image offline, so a package missing from the image fails CI.
- `cypress-io/github-action` is updated from `7.4.4` to `7.4.6` in CI.

### Fixed

- The README comparison table now correctly describes Juice Shop's CTF mode (`CTF_KEY`, CTFd/RootTheBox/FBCTF export) and CVE coverage.

### Security

- The Docker lab no longer restarts automatically; after a host reboot, start it again with `npm run docker:up`.

## [v2.21.1] - 2026-09-22

[Release notes](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.21.1)

### Fixed

- `npm start` and `npm run dev` bind `localhost` instead of `127.0.0.1`, so the printed startup URL no longer breaks login.

## [v2.21.0] - 2026-09-22

[Release notes](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.21.0)

### Added

- The SQL injection challenges (product search, order search, `X-Forwarded-For` tracking, second-order reviews) now require exfiltrating a canary from `internal_secrets`.
- The CSRF flag now requires a request fired by a page, not a bare `PATCH` from a terminal.
- `npm run db:upgrade` brings existing installs up to the Prisma schema without wiping data; Docker's entrypoint runs it on start.
- New `npm run start:network` script binds all interfaces when network access is intentional.

### Changed

- **Breaking:** The four SQL injection flags now require reading a canary from `internal_secrets`, and the CSRF flag a page-issued request; run `npm run db:upgrade` or `docker compose up -d --build` to create the canary rows.
- **Breaking:** The app refuses to start against a database behind `prisma/schema.prisma`; run `npm run db:upgrade` or `docker compose up -d --build`, or start over with `npm run docker:reset` or `npm run setup`.
- **Breaking:** `npm start`, `npm run dev` and Prisma Studio from `npm run setup` now bind `127.0.0.1`; use `npm run start:network` to bind `0.0.0.0` for remote access; Docker users are unaffected.
- The four SQL injection routes share one flags-table guard and a sanitizer matching `OSS{`, so `sqlite_master` output reaches players.
- Walkthrough corrections cover the reviews table recovery (`db:seed` alone fails), CSRF gate, `sameSite=lax` behaviour and SQLi command outputs.
- Regression tests cover the CSRF flag via the shipped exploit page, canary slugs, upgrade-preserved ids and the padding oracle probe.
- The documentation site runs on Astro 7, with `@shikijs/transformers`, `satori`, ESLint, `typescript-eslint` and `eslint-plugin-astro` updated.
- Application, docs and CLI dependencies are updated, including `degit` 3 and `ora` in the CLI.
- CI uses `cypress-io/github-action` 7.4.4 and `docker/build-push-action` 7.4.0.
- The CLI publish job no longer runs an unused install step.

### Fixed

- The `X-Forwarded-For` flag is no longer handed to every visitor arriving from localhost.
- The second-order SQLi flag is refused when the canary comes from a review body instead of the stored filter value.
- The admin review panel clears its error and captured flag when the filter changes.
- Injectable responses no longer leak the hints table or the tracking `sessionId`.

### Security

- `npm start`, `npm run dev` and Prisma Studio from `npm run setup` bind `127.0.0.1` by default.
- The `create-oss-store` CLI is published to npm with build provenance.

## [v2.20.0] - 2026-09-09

[Release notes](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.20.0)

### Added

- Shareable Hall of Fame badges can be generated for completed challenges.
- README project statistics come from a self-hosted stats card instead of the third-party Repography service.
- Labs scaffolded with `create-oss-store` no longer include the upstream `.github` directory and its inherited workflows.

### Changed

- **Breaking:** Node.js 22, declared in `.nvmrc`, is now the minimum version for the store, tests, Docker image, CI and `create-oss-store`, which fails fast on older runtimes; Node 20 users must upgrade to Node 22 (`nvm use`) before installing.
- Automated PR comments are shorter and only include information the PR page cannot already show.
- Open Graph image generation loads Satori fonts once per build instead of once per image, cutting build time.
- Informational pages and the support page share one page hero component, with a documented convention for component props types.
- SQL injection detection is consolidated in one shared helper instead of being duplicated.
- Documentation gains a getting started section and VWAD and TryHackMe badges, and references `package.json` for framework versions.
- The inert `.degitignore` file is removed.
- CI dependencies are updated: `cypress-io/github-action` `7.4.1` → `7.4.3` and `actions/deploy-pages` `5.0.0` → `5.0.1`.

### Fixed

- `create-oss-store` reports real build errors, installs the matching release tag, recovers corrupted degit caches and cleans up partial installs.
- Mobile navigation is interactive and mounts its items only while the menu is open.
- Newsletter submissions are handled correctly.
- The newsletter email field and the FlagChecker and HintPanel close buttons expose accessible names to screen readers.
- Challenge titles render the `npm` slug in lowercase, as in "npm Supply Chain Typosquat".
- Slug formatting uses the shared `formatSlug` helper, and the footer links to the MIT license.
- PR automation requires both permission scopes, not just one, before commenting.

### Security

- New `SECURITY.md` describes the vulnerability reporting process for this intentionally vulnerable project.
- The react2shell test suite acts as an exploit canary, failing if the intended vulnerability becomes unreachable.

## [v2.19.0] - 2026-08-14

[Release notes](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.19.0)

### Added

- Community discussions have their own routed section, so threads are linkable and easier to browse.
- The TryHackMe room is linked from the documentation site and from a reorganized footer.

### Changed

- **Breaking:** Node.js 20 or later is now required: the `create-oss-store` `engines` field moved from `>=18.0.0` to `>=20.0.0`, enforced workspace-wide; upgrade to Node.js 20 LTS or later before installing or updating.
- The Astro documentation site no longer depends on React and Giscus, reducing its footprint.
- Docker examples bind to `localhost`, and the shared-instance setup for CTF events is removed to avoid unsafe network exposure.
- The educator setup guide states the Node 20 requirement.
- The README shows a storefront screenshot, the AstroPaper demo post is removed, and the AstroPaper link targets "Adding new posts".

### Fixed

- Flag values stay hidden until their challenge is solved, restoring the intended difficulty.
- The MCP poisoning challenge can be reached and solved from Docker without additional configuration.
- Discussion topics carry the challenge in their title instead of a dropdown selector.

## [v2.18.0] - 2026-08-11

[Release notes](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.18.0)

### Added

- New challenge: a Partner API vulnerable to RS256/HS256 JWT algorithm confusion, letting players forge tokens it accepts.
- A `challenges.json` feed generated from the roadmap exposes each challenge's category and estimated completion time.
- The Hall of Fame shows project contributors alongside players, fetched from the GitHub API at build time.
- New topic pages, JSON-LD structured data and roadmap cross-linking make challenges easier to find from search engines.
- A dismissible Star-on-GitHub callout appears on writeups and the roadmap.

### Changed

- **Breaking:** A new `channel` column on `supplier_orders` requires existing installs, including mounted Docker volumes, to run `npm run db:push && npm run db:seed`, else `/api/partner/orders` and `/api/admin/suppliers` return 500; set `PARTNER_SIGNING_KEY_PATH` if your data directory is read-only.
- The educator catalog documentation follows the roadmap numbering, and the educator kit and About page link the `challenges.json` feed.
- The documentation includes a Docker image resource link.
- Repository URLs live in a single configuration module instead of being hardcoded throughout the app.
- A parity test and contributor checklist stop partially registered new challenges from being merged.
- Minor and patch-level project dependencies are updated.
- CI workflows use updated `actions/checkout`, `actions/setup-node`, `docker/login-action`, `docker/build-push-action` and `cypress-io/github-action` actions.

### Fixed

- "Edit this page" links point at the `main` branch instead of `develop`.
- Inconsistencies in the JSON-LD structured data are corrected.
- The repository enforces LF line endings, resolving checkout issues.

## [v2.17.0] - 2026-06-18

[Release notes](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.17.0)

### Added

- New challenge: Broken Function Level Authorization, featuring a live stream hijack scenario.

### Changed

- The About page learning objectives now match the available lab challenges.
- The padding oracle write-up now matches how the challenge actually behaves.

## [v2.16.3] - 2026-06-11

[Release notes](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.16.3)

### Added

- The setup script, npx installer and Docker entrypoint show a reminder inviting users to star the project on GitHub.

### Changed

- The README has a verified comparison table for evaluating the project against other deliberately vulnerable applications.
- The `EDUCATORS.md` guide is shorter, more focused and easier to read.
- The CI dependencies `actions/checkout` and `cypress-io/github-action` are updated.

## [v2.16.2] - 2026-06-04

[Release notes](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.16.2)

### Added

- A first-visit **onboarding guide** helps new users get started, with a dedicated practice flag for guided hands-on learning.

### Changed

- The supply-chain attack write-up now connects the **Shai-Hulud** scenario with rules-file poisoning, clarifying how the two techniques relate.
- Project dependencies received patch-level updates.
- The CI/CD pipeline upgrades `docker/build-push-action` (`7.1.0` → `7.2.0`) and `docker/login-action` (`4.1.0` → `4.2.0`).

### Fixed

- The displayed curriculum chapter count now accurately reflects the available content.

## [v2.16.1] - 2026-05-18

[Release notes](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.16.1)

### Added

- A new pedagogical roadmap page offers a structured learning path through the challenges and walkthroughs.

### Changed

- IDOR/BOLA labels and chained challenge numbering are now consistent across walkthroughs.
- The supply-chain poisoned-rules-chain walkthrough no longer contains an unnecessary screenshot.
- `typescript-eslint` is bumped to 8.59.2 for TypeScript 6 compatibility.
- Patch-level dependencies are updated across the project.
- `cypress-io/github-action` is bumped from 7.1.10 to 7.3.0 in CI workflows.

### Fixed

- The Docker image now includes `packages/react-toastfy`, so the supply-chain challenge is reachable again when the lab runs via Docker.

## [v2.16.0] - 2026-05-04

[Release notes](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.16.0)

### Added

- New supply-chain attack scenario: a typosquat package combined with an AI rules file backdoor plants a runtime backdoor.

### Changed

- `cypress-io/github-action` is bumped from `7.1.9` to `7.1.10`.

### Security

- API route inputs are validated with Zod schemas for strict, type-safe request parsing.

## [v2.15.1] - 2026-04-28

[Release notes](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.15.1)

### Added

- OWASP Top 10 references across the platform now use the 2025 edition instead of the 2021 edition.
- Flags carry CWE and OWASP identifiers, and CVE/CWE/OWASP badges link to their external reference pages.
- Flag values on the `/flags` page stay masked until the user finds them.
- In-app vulnerability pages link directly to the corresponding walkthrough site.
- The site footer includes a dev.to social link.

### Changed

- `@types/canvas-confetti` and `@types/jsonwebtoken` moved from `dependencies` to `devDependencies`, since they are only needed at build time.
- The CSRF challenge alert is told from the victim's perspective for clearer storytelling.
- Rewritten docs clarify `content/` versus `docs/`, add a CSRF admin order update writeup, and list Insecure Randomness in `EDUCATORS.md`.
- CI workflows use `actions/setup-node` 6.4.0, up from 4.4.0.

### Fixed

- The AES-CBC padding oracle tamper test is deterministic, so it no longer fails intermittently.
- The `FlagCategory` type includes the previously missing `INSECURE_DESIGN` category.

## [v2.15.0] - 2026-04-22

[Release notes](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.15.0)

### Added

- New challenge: **Insecure Randomness Gift Card**, which shows the vulnerabilities that come from predictable random number generation.
- A new path traversal writeup is published, and its walkthrough is linked so learners can find it more easily.

### Fixed

- TypeScript is pinned to `5.9.3` to match the `@astrojs/check` peer dependency and prevent version mismatches.

## [v2.14.2] - 2026-04-18

[Release notes](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.14.2)

### Changed

- The SIEM log viewer is paginated server-side for smoother navigation of large log volumes.
- Application logging uses Pino structured logging instead of `console`.
- The welcome PR message shows contribution stats, size labels and CI information.
- Authentication uses unified `withAuth` and `withAdminAuth` wrappers instead of scattered manual checks.
- New writeup for the `NEXT_PUBLIC_` environment variable leak challenge.
- The plaintext-password-in-logs writeup reflects the Pino logging migration.
- The public-env and info-disclosure flags link to their walkthroughs through `walkthroughSlug`.
- Dependabot bumps GitHub Actions: `actions/github-script`, `actions/upload-artifact`, `actions/upload-pages-artifact`, `docker/build-push-action`, `docker/login-action`, `cypress-io/github-action`.

### Fixed

- The `NEXT_PUBLIC_` environment variable leak challenge works again in production builds (`npm start`) through an `X-Payment-Auth` header.
- The padding oracle test is deterministic, flipping the entire block to eliminate flaky runs.

## [v2.14.1] - 2026-04-04

[Release notes](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.14.1)

### Added

- New walkthrough for the "Information Disclosure via API Error Message" vulnerability.

### Changed

- The "Information Disclosure via API Error Message" vulnerability's export fields use checkboxes and an array, not a comma-separated string.
- `actions/deploy-pages` is bumped from `4.0.5` to `5.0.0`.

### Fixed

- The race condition coupon flag is now categorized as `INSECURE_DESIGN`.
- An unused flag type definition was deleted.

## [v2.14.0] - 2026-03-28

[Release notes](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.14.0)

### Added

- New challenge: a race condition vulnerability (OWASP A01, A04) where concurrent requests exploit non-atomic read-then-write operations on shared state.

### Fixed

- The stale `screen.png` asset, wrongly left in the codebase, is removed.

## [v2.13.0] - 2026-03-22

[Release notes](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.13.0)

### Added

- New challenge: Middleware authorization bypass, based on the Next.js middleware authorization bypass (CVE-2025-29927).
- A contextual support banner appears after a user captures a flag.
- New educator kit for teaching with the lab, with OWASP grids, syllabus templates and a student report template.

### Changed

- The documentation site moves from Astro 5 to Astro 6 and `@astrojs/react 5.0.0`, and experimental config options become stable.
- CI pipelines run on Node.js 22 for Astro 6 compatibility.
- Dependency updates: `chalk` and `ora` in create-oss-store, `cypress-io/github-action` 7.1.8, and latest minor versions of `@astrojs/rss`, `@astrojs/check` and `slugify`.

### Fixed

- The Mistral model is pinned to `mistral-small-2603` and checked by an availability test to prevent model availability issues.
- The obsolete Astro experimental flag, which could cause warnings or build issues, is removed from the configuration.

## [v2.12.0] - 2026-03-14

[Release notes](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.12.0)

### Added

- New challenge: MCP Malicious Server, where poisoned MCP tool responses drive indirect prompt injection to bypass access control, plus SSRF.

### Changed

- Business logic tests now cover the unit, API and E2E layers.

### Fixed

- Authentication-dependent header components no longer cause client/server hydration mismatches.

## [v2.11.0] - 2026-03-13

[Release notes](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.11.0)

### Added

- New challenge: AES-CBC padding oracle vulnerability in a secure document sharing scenario.

### Changed

- CI gains quality checks, a Docker build workflow, npm Dependabot configuration and automated PR welcome messages for new contributors.
- GitHub Actions dependencies move to new major versions: `actions/checkout`, `actions/setup-node`, `actions/upload-pages-artifact`, `cypress-io/github-action` and `docker/login-action`.

### Security

- CI workflows are hardened with tighter GitHub Actions permissions, actions pinned to commit SHAs, and script injection mitigations.
- Dependabot now updates only `/docs` and `/packages`, excluding the intentionally vulnerable root application.

## [v2.10.0] - 2026-03-05

[Release notes](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.10.0)

### Added

- New challenges: two profile takeover flags built on a self-XSS and CSRF chain.
- Docker images are published automatically to Docker Hub on each release.

### Changed

- The README and lab walkthroughs now offer Docker as a setup alternative, with direct links to Docker Hub.
- The weak session flag now has its missing `walkthroughSlug`.

## [v2.9.0] - 2026-03-01

[Release notes](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.9.0)

### Added

- New challenge: open redirect on the login form, to practice finding and exploiting open redirect flaws in authentication flows.

### Changed

- New walkthrough for the weak session management vulnerability.
- Walkthrough texts, the README and the CONTRIBUTING documentation are improved.
- Astro is upgraded to the latest version.

## [v2.8.0] - 2026-02-26

[Release notes](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.8.0)

### Added

- The application runs entirely via Docker and docker-compose, with `npm run docker:*` helper scripts; no local Node.js needed.
- New challenge: Insecure password reset, a password reset flow with predictable, weak token generation.

### Changed

- A pull request template standardizes contributions.

### Fixed

- Prisma Studio no longer opens a browser automatically during setup.
- The plaintext password test uses a more specific assertion to avoid flaky results.

## [v2.7.0] - 2026-02-22

[Release notes](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.7.0)

### Added

- An automated test suite of unit, API and Cypress end-to-end tests guards existing flags against regressions.
- The develop branch is gone; changes reach main only through pull requests with CI-run tests.

### Changed

- The README and CONTRIBUTING documentation is updated.
- GitHub Pages dependencies are upgraded.

## [v2.6.0] - 2026-02-18

[Release notes](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.6.0)

### Added

- New challenge: XXE injection in the supplier order import enables arbitrary file reads; admin access is required.
- Blog post images open in a fullscreen lightbox, closed with the close button, Escape key, or a backdrop click.

### Changed

- The admin dashboard uses a responsive card grid instead of a button list, with consistent “Back to admin” navigation.

## [v2.5.0] - 2026-02-17

[Release notes](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.5.0)

### Added

- New challenge: Plaintext Password in Logs, where the login route leaks credentials readable from the SIEM dashboard at `/monitoring/siem`.
- New walkthrough for the Product Search SQL Injection flag.

### Changed

- The seed file now includes the missing walkthrough for the Malicious File Upload / Stored XSS vulnerability.
- The repository now has a "Good First Issues" link and a forks badge.

### Fixed

- Documentation links for flags in the player dashboard now point to the correct pages.

## [v2.4.0] - 2026-02-12

[Release notes](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.4.0)

### Added

- New admin review moderation workflow with display names and author filtering, plus a second-order SQL injection challenge in its filters.
- CTF flags now have a progressive hints system to guide players through challenges.

### Changed

- Auth tokens move from `localStorage` to HTTP-only cookies with `sameSite:lax`, for more realistic CSRF scenarios.
- Authentication now relies on HTTP-only cookie-based JWTs for a more realistic browser security model.
- The frontend API layer automatically includes credentials in requests.
- Documentation and walkthroughs are updated for the new authentication and vulnerability mechanics.

## [v2.3.1] - 2026-02-07

[Release notes](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.3.1)

### Added

- New walkthrough for the Brute Force flag challenge.

### Changed

- Project documentation moved from `CLAUDE.md` to Cursor rules and `AGENTS.md`.
- The README shows new Repography statistics.
- The BOLA vulnerability documentation now has its missing `walkthroughSlug` field.

### Fixed

- The Stored XSS challenge works in production builds (`npm start`): uploaded SVG files are served through the new `/api/uploads/` API route.

## [v2.3.0] - 2026-01-31

[Release notes](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.3.0)

### Added

- New challenge: the **BOLA (Broken Object Level Authorization)** vulnerability.

### Changed

- The **prompt injection** documentation now has clearer explanations and more concrete examples.
- A minor typo in `CONTRIBUTING.md` is corrected.

## [v2.2.0] - 2026-01-25

[Release notes](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.2.0)

### Added

- New challenge: AI Assistant Prompt Injection, where crafted inputs bypass the assistant's constraints to reveal sensitive information.

## [v2.1.1] - 2026-01-25

[Release notes](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.1.1)

### Added

- The app has 404 and 500 error pages for better error handling.
- A PDF invoice generation system creates an invoice automatically when an order is placed.
- The admin documents page supports directory browsing and PDF viewing.

### Changed

- The documents page moved to the admin section, with proper access controls.

### Fixed

- The npm package installation now includes the build step.
- A typo in the Astro homepage command documentation is corrected.

## [v2.1.0] - 2026-01-24

[Release notes](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.1.0)

### Added

- New challenge: X-Forwarded-For Header SQL Injection, an SQL injection through the `X-Forwarded-For` header with silent visitor tracking via `VisitorTracker`.
- New Admin Analytics page: the `/admin/analytics` dashboard uses vulnerability-specific rendering techniques.
- New Visitor Tracking endpoint: `/api/tracking` processes visitor data and detects SQL injection attempts.
- New walkthrough in the exploitation documentation for the X-Forwarded-For SQL injection vulnerability.

### Changed

- The File Upload XSS Attack Chain extends the malicious file upload vulnerability to show cross-user impact scenarios.
- New exploitation guides with detailed walkthroughs for attacks related to file uploads.

## [v2.0.0] - 2026-01-23

[Release notes](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.0.0)

### Added

- The new Player Dashboard at `/player-dashboard` tracks CTF progress by completion, difficulty, category and elapsed time.
- Flag progress is stored in the database instead of browser `localStorage`, persisting across sessions with a timestamp per captured flag.
- A searchable walkthrough documentation site covers XSS, JWT, IDOR, SSRF, mass assignment, weak cryptography and client-side logic flaws.

### Changed

- **Breaking:** Flag progress is no longer stored in browser `localStorage` but in the database, which impacts existing players whose progress was stored locally.
- The documentation site build and configuration fully support GitHub Pages subpath deployments.
- CI/CD workflows deploy the documentation from the main branch only.

### Fixed

- Walkthrough site fixes cover Pagefind search, breadcrumbs, Astro URLs, Open Graph images, Next.js TypeScript builds and `.nojekyll` on GitHub Pages.

### Security

- The XSS challenge no longer discloses the flag automatically; players must chain XSS with same-origin static file access.
- The JWT vulnerability now uses HS256 with a weak secret instead of `alg: none`.

## [v1.11.0] - 2026-01-17

[Release notes](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v1.11.0)

### Added

- New challenge: Brute Force, where `vis.bruta@example.com` has no rate limiting and a weak password from common wordlists.
- The CSRF exploit demonstration now uses a realistic Mail mode interface with a PayPal security alert phishing scenario.

### Changed

- The News page leaked data section shows email addresses alongside password hashes, with some hashes redacted.
- A persistent flag toast notification appears on the home page after a challenge is completed.
- The CSRF documentation clarifies localStorage-based versus cookie-based scenarios and same-origin versus cross-site attack vectors.
- Flag seeding uses upsert operations instead of createMany, so new flags can be added without recreating the entire dataset.

## [v1.10.1] - 2026-01-16

[Release notes](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v1.10.1)

### Fixed

- The CSRF vulnerability demonstration works again after the token-based authentication migration, with its exploit reading tokens from local storage.

## [v1.10.0] - 2026-01-16

[Release notes](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v1.10.0)

### Added

- New page: Hall of Fame, a community-driven page of player profiles.
- New flags: SQL injection in product search, and session fixation with weak session management.

### Changed

- The Weak MD5 hashing vulnerability requires chained exploits such as SQL injection; the hash is no longer shown on `/news`.
- The `ROADMAP.md` file is replaced by a GitHub project, and related links are updated.
- Redundant cookie-based authentication code is removed.

## [v1.9.0] - 2026-01-13

[Release notes](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v1.9.0)

### Added

- New challenge: malicious SVG file upload with stored XSS on the admin product image management page.
- The application now has a favicon.

### Changed

- The README header is redesigned with a centered layout and updated copy.
- ASCII art now appears in the `create-oss-store` CLI, `setup.sh` and the browser console welcome message.
- The badges section shows additional metrics.
- A new `CLAUDE.md` file provides project context and documentation references.

### Fixed

- The writeups link in the footer is fixed.

## [v1.8.0] - 2026-01-12

[Release notes](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v1.8.0)

### Added

- Flags carry difficulty and category metadata, with a UI to classify and navigate challenges.
- New challenge: an Information Disclosure flag exposed through API errors.
- The Flag Checker component links directly to documentation pages.
- The README includes a Repography integration, and the site footer links to Writeups.

### Changed

- A new `ROADMAP.md` documents project direction, and `README.md` and `CONTRIBUTING.md` are updated with contribution guidelines.

### Fixed

- The `User` type is exported from `client-auth` again, so downstream consumers can use it.

## [v1.7.0] - 2026-01-08

[Release notes](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v1.7.0)

### Added

- New challenge: a SQL injection flag.
- Special styling appears once all flags are found.

### Changed

- A new `useAuth` hook and shared authentication utilities cut duplicated code across components.
- Shared types now live in one place, `lib/types`.
- The API layer now goes through a single API client, `lib/api.ts`, with typed methods.
- Server-side auth moved from `lib/auth.ts` to `lib/server-auth.ts`, and client-side auth from `lib/utils/auth.ts` to `lib/client-auth.ts`.
- Base URL configuration is now set in one place.
- `getDatabaseUrl` now lives in a shared module.
- The unused `lib/vulnerabilities.ts` file is removed.
- A typo in the CSRF flag documentation is corrected.

### Fixed

- The CLI publish workflow now allows the same version to be published again.

## [v1.6.0] - 2026-01-07

[Release notes](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v1.6.0)

### Added

- New challenge: an SSRF flag expands the list of supported vulnerabilities and attack scenarios.
- Flags are displayed through a generic component, making the UI more consistent and new flag types easier to add.

### Changed

- The flag validation button plays a small animation, making the validation flow feel more responsive and clearer.
- Quick start commands now sit at the top of the showcase hero section, so new users start without scrolling.
- The showcase website setup instructions are clarified, and the README shows an npm badge with the latest package version.

## [1.5.0] - 2026-01-02

[Release notes](https://github.com/kOaDT/oss-oopssec-store/releases/tag/1.5.0)

### Added

- `npx create-oss-store my-ctf-lab` sets up the store with seeded CTF flags; then run `cd my-ctf-lab` and `npm run dev`.
- The CLI package lives in `packages/create-oss-store/` and is published on npm.
- The `.github/workflows/publish-cli.yml` workflow publishes the CLI automatically on each new release.

### Changed

- The showcase site's navigation menu now responds correctly to screen size.
- The README shows GitHub shields for license, release and stars, and its SEO is better.
- `.env` is no longer tracked in version control because the setup script generates it.

## [1.4.0] - 2025-12-28

[Release notes](https://github.com/kOaDT/oss-oopssec-store/releases/tag/1.4.0)

### Added

- New challenge: Mass Assignment/Parameter Pollution, letting attackers modify fields that should not be user-controllable.
- New challenge: Path Traversal, using sequences like `../` to access files outside the intended directory.

### Changed

- The client-side (CSR) price manipulation flag is passed as a URL parameter and shown on the order confirmation page.

## [1.3.0] - 2025-12-22

[Release notes](https://github.com/kOaDT/oss-oopssec-store/releases/tag/1.3.0)

### Added

- New challenge: IDOR flag, an Insecure Direct Object Reference that lets attackers reach unauthorized resources by manipulating identifiers.
- New challenge: XSS flag, a Cross-Site Scripting vulnerability that shows client-side code injection and its impact.
- New challenge: CSRF flag, a Cross-Site Request Forgery vulnerability that exposes missing or misconfigured CSRF protections.

### Changed

- The news page no longer shows an unneeded MD5 reference.

[v2.23.0]: https://github.com/kOaDT/oss-oopssec-store/compare/v2.22.0...v2.23.0
[v2.22.0]: https://github.com/kOaDT/oss-oopssec-store/compare/v2.21.1...v2.22.0
[v2.21.1]: https://github.com/kOaDT/oss-oopssec-store/compare/v2.21.0...v2.21.1
[v2.21.0]: https://github.com/kOaDT/oss-oopssec-store/compare/v2.20.0...v2.21.0
[v2.20.0]: https://github.com/kOaDT/oss-oopssec-store/compare/v2.19.0...v2.20.0
[v2.19.0]: https://github.com/kOaDT/oss-oopssec-store/compare/v2.18.0...v2.19.0
[v2.18.0]: https://github.com/kOaDT/oss-oopssec-store/compare/v2.17.0...v2.18.0
[v2.17.0]: https://github.com/kOaDT/oss-oopssec-store/compare/v2.16.3...v2.17.0
[v2.16.3]: https://github.com/kOaDT/oss-oopssec-store/compare/v2.16.2...v2.16.3
[v2.16.2]: https://github.com/kOaDT/oss-oopssec-store/compare/v2.16.1...v2.16.2
[v2.16.1]: https://github.com/kOaDT/oss-oopssec-store/compare/v2.16.0...v2.16.1
[v2.16.0]: https://github.com/kOaDT/oss-oopssec-store/compare/v2.15.1...v2.16.0
[v2.15.1]: https://github.com/kOaDT/oss-oopssec-store/compare/v2.15.0...v2.15.1
[v2.15.0]: https://github.com/kOaDT/oss-oopssec-store/compare/v2.14.2...v2.15.0
[v2.14.2]: https://github.com/kOaDT/oss-oopssec-store/compare/v2.14.1...v2.14.2
[v2.14.1]: https://github.com/kOaDT/oss-oopssec-store/compare/v2.14.0...v2.14.1
[v2.14.0]: https://github.com/kOaDT/oss-oopssec-store/compare/v2.13.0...v2.14.0
[v2.13.0]: https://github.com/kOaDT/oss-oopssec-store/compare/v2.12.0...v2.13.0
[v2.12.0]: https://github.com/kOaDT/oss-oopssec-store/compare/v2.11.0...v2.12.0
[v2.11.0]: https://github.com/kOaDT/oss-oopssec-store/compare/v2.10.0...v2.11.0
[v2.10.0]: https://github.com/kOaDT/oss-oopssec-store/compare/v2.9.0...v2.10.0
[v2.9.0]: https://github.com/kOaDT/oss-oopssec-store/compare/v2.8.0...v2.9.0
[v2.8.0]: https://github.com/kOaDT/oss-oopssec-store/compare/v2.7.0...v2.8.0
[v2.7.0]: https://github.com/kOaDT/oss-oopssec-store/compare/v2.6.0...v2.7.0
[v2.6.0]: https://github.com/kOaDT/oss-oopssec-store/compare/v2.5.0...v2.6.0
[v2.5.0]: https://github.com/kOaDT/oss-oopssec-store/compare/v2.4.0...v2.5.0
[v2.4.0]: https://github.com/kOaDT/oss-oopssec-store/compare/v2.3.1...v2.4.0
[v2.3.1]: https://github.com/kOaDT/oss-oopssec-store/compare/v2.3.0...v2.3.1
[v2.3.0]: https://github.com/kOaDT/oss-oopssec-store/compare/v2.2.0...v2.3.0
[v2.2.0]: https://github.com/kOaDT/oss-oopssec-store/compare/v2.1.1...v2.2.0
[v2.1.1]: https://github.com/kOaDT/oss-oopssec-store/compare/v2.1.0...v2.1.1
[v2.1.0]: https://github.com/kOaDT/oss-oopssec-store/compare/v2.0.0...v2.1.0
[v2.0.0]: https://github.com/kOaDT/oss-oopssec-store/compare/v1.11.0...v2.0.0
[v1.11.0]: https://github.com/kOaDT/oss-oopssec-store/compare/v1.10.1...v1.11.0
[v1.10.1]: https://github.com/kOaDT/oss-oopssec-store/compare/v1.10.0...v1.10.1
[v1.10.0]: https://github.com/kOaDT/oss-oopssec-store/compare/v1.9.0...v1.10.0
[v1.9.0]: https://github.com/kOaDT/oss-oopssec-store/compare/v1.8.0...v1.9.0
[v1.8.0]: https://github.com/kOaDT/oss-oopssec-store/compare/v1.7.0...v1.8.0
[v1.7.0]: https://github.com/kOaDT/oss-oopssec-store/compare/v1.6.0...v1.7.0
[v1.6.0]: https://github.com/kOaDT/oss-oopssec-store/compare/1.5.0...v1.6.0
[1.5.0]: https://github.com/kOaDT/oss-oopssec-store/compare/1.4.0...1.5.0
[1.4.0]: https://github.com/kOaDT/oss-oopssec-store/compare/1.3.0...1.4.0
[1.3.0]: https://github.com/kOaDT/oss-oopssec-store/releases/tag/1.3.0
