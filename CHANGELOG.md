# Changelog

All notable changes to OopsSec Store are documented here. This changelog follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and links to the official GitHub release notes for full details.

**Maintenance:** This file is maintained manually. Update it when publishing each release, using the published release notes and keeping summaries short.

## [v2.22.0](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.22.0) - 2026-10-07

### Added

- Community Resources on the Hall of Fame page.

### Changed

- Smaller Docker image.
- Docker startup fails fast on a missing package.
- Documentation. The About page on the docs site now matches the README pitch.

### Fixed

- Accurate Juice Shop comparison.

### Security

- The Docker lab no longer restarts on its own.

## [v2.21.1](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.21.1) - 2026-09-22

### Fixed

- Corrected local Node.js server binding to `localhost` to prevent browser/API origin mismatches and CORS login failures.

## [v2.21.0](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.21.0) - 2026-09-22

### Added

- SQL injection challenges now reward real exfiltration.
- The CSRF flag now requires a request a page actually fired.
- Existing installs can catch up without being wiped.

### Changed

- The four SQL injection routes share a single flags-table guard and response sanitizer.
- Documentation corrections across the walkthroughs: the reviews table recovery command (`db:seed` alone fails once the table is dropped.
- Expanded regression coverage for CSRF, SQL injection canaries, database upgrades, and padding-oracle behavior.

### Fixed

- The `X-Forwarded-For` flag is no longer handed to every visitor arriving from localhost.
- The second-order SQLi flag is refused when the canary is carried by a review body rather than exfiltrated through the stored filter value.
- The admin review panel now clears its error and captured flag when the filter changes, instead of carrying stale state between queries.

### Security

- The lab binds loopback by default.
- The `create-oss-store` CLI is published to npm with build provenance.

## [v2.20.0](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.20.0) - 2026-09-09

### Added

- Shareable Hall of Fame badges can now be generated for completed challenges.
- The README project statistics are now produced by a self-hosted stats card instead of the third-party Repography service, removing an external dependency from the project page.
- Labs scaffolded with `create-oss-store` no longer carry the upstream `.github` directory, so new projects start without inherited workflows.

### Changed

- Node.js 22 is now the minimum supported version.
- Automated PR comments are much shorter and limited to information the PR page cannot already show.
- Open Graph image generation loads Satori fonts once per build rather than once per image, cutting build time.

### Fixed

- Failed builds now surface the real error message, and large command output no longer hangs the process on an unread pipe.
- Both output streams are reported when a setup command fails.
- The CLI installs the matching release tag instead of `main`, so scaffolded projects match the published version.

### Security

- Added `SECURITY.md` describing the vulnerability reporting process for this intentionally vulnerable project.
- The react2shell test suite now acts as a real exploit canary, failing if the intended vulnerability stops being reachable.

## [v2.19.0](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.19.0) - 2026-08-14

### Added

- Community discussions are now a dedicated, routed space.
- The TryHackMe room is now surfaced across the project.

### Changed

- Removed the React and Giscus dependencies from the Astro documentation site, reducing its footprint.
- Docker examples are now bound to `localhost`, and the shared-instance setup for CTF events has been removed to avoid unsafe network exposure.
- The educator setup guide now states the Node 20 requirement.

### Fixed

- Flag values are no longer exposed before a challenge is solved.
- The MCP poisoning challenge is now reachable from Docker.
- Discussion topics now carry the challenge in the title.

## [v2.18.0](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.18.0) - 2026-08-11

### Added

- New challenge: Partner API with a JWT algorithm confusion flaw.
- Machine-readable challenge feed.
- Improved discoverability.

### Changed

- The educator catalog documentation is now aligned with the roadmap numbering, and the `challenges.json` feed is linked from both the educator kit and the About page.
- Added a Docker image resource link to the documentation.
- Repository URLs are centralized in a single configuration module instead of being hardcoded throughout the app.

### Fixed

- Edit page links now point at the `main` branch instead of `develop`, so "edit this page" no longer leads to a stale or missing target.
- Corrected inconsistencies in the JSON-LD structured data.
- Enforced LF line endings across the repository, fixing checkout issues reported in #239.

## [v2.17.0](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.17.0) - 2026-06-18

### Added

- Added a new Broken Function Level Authorization challenge featuring a live stream hijack scenario, expanding the hands-on lab catalog.

### Changed

- Updated the _About_ page learning objectives so they accurately reflect the available lab challenges.
- Corrected the padding oracle write-up to align with the challenge's actual behavior.

## [v2.16.3](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.16.3) - 2026-06-11

### Added

- The setup script, npx installer, and Docker entrypoint now display a reminder inviting users to star the project on GitHub, helping support the project's visibility.

### Changed

- Added a verified comparison table to the README, making it easier to evaluate the project against alternative deliberately-vulnerable applications.
- Streamlined the EDUCATORS.md guide for a more focused and readable experience.
- Updated CI dependencies.

## [v2.16.2](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.16.2) - 2026-06-04

### Added

- Added a first-visit onboarding guide to help new users get started, including a dedicated practice flag for guided hands-on learning.

### Changed

- Expanded the supply-chain attack write-up to connect the Shai-Hulud scenario with rules-file poisoning, clarifying the relationship between the two techniques.
- Applied patch-level updates across project dependencies.
- Upgraded `docker/build-push-action` (7.1.0 → 7.2.0) and `docker/login-action` (4.1.0 → 4.2.0) in the CI/CD pipeline.

### Fixed

- Corrected the displayed curriculum chapter count so it accurately reflects the available content.

## [v2.16.1](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.16.1) - 2026-05-18

### Added

- Added a new pedagogical roadmap available at https://koadt.github.io/oss-oopssec-store/roadmap, offering a structured learning path for users navigating the challenges and walkthroughs.

### Changed

- Corrected IDOR/BOLA labels and chained challenge numbering for consistency across walkthroughs.
- Removed an unnecessary screenshot from the supply-chain poisoned-rules-chain walkthrough.
- Bumped `typescript-eslint` to 8.59.2 for TypeScript 6 compatibility.

### Fixed

- Fixed the Docker image build so the `packages/react-toastfy` package is now included.

## [v2.16.0](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.16.0) - 2026-05-04

### Added

- New supply-chain attack scenario.

### Changed

- Bumped `cypress-io/github-action` from `7.1.9` to `7.1.10` (patch update) via Dependabot.

### Security

- Input validation hardening.

## [v2.15.1](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.15.1) - 2026-04-28

### Added

- Migrated OWASP Top 10 references from the 2021 edition to the 2025 edition across the platform.
- Added CWE and OWASP identifiers to flags, and linked CVE/CWE/OWASP badges to their external reference pages.
- Flag values on the `/flags` page are now masked until they have been found by the user, preserving the challenge experience.

### Changed

- Moved `@types/canvas-confetti` and `@types/jsonwebtoken` from `dependencies` to `devDependencies`, since they are only needed at build time @TrivCodez https://github.com/kOaDT/oss-oopssec-store/issues/79.
- Reframed the CSRF challenge alert from the victim's perspective for clearer storytelling.
- Clarified contribution guides and updated CSRF and educator documentation.

### Fixed

- Made the AES-CBC padding oracle tamper test deterministic, eliminating intermittent failures.
- Fixed a pre-existing gap where the `INSECURE_DESIGN` category was missing from the `FlagCategory` type.

## [v2.15.0](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.15.0) - 2026-04-22

### Added

- Added a new Insecure Randomness Gift Card challenge, demonstrating vulnerabilities tied to predictable random number generation.
- Published a new path traversal writeup and linked its walkthrough for improved learner navigation.

### Fixed

- Pinned TypeScript to 5.9.3 to align with the `@astrojs/check` peer dependency requirement and prevent version mismatch issues.

## [v2.14.2](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.14.2) - 2026-04-18

### Changed

- Added server-side pagination to the SIEM log viewer for smoother navigation of large log volumes.
- Migrated application logging from `console` to Pino structured logging.
- Enhanced the welcome PR message with contribution stats, size labels, and CI information.

### Fixed

- Fixed the `NEXT_PUBLIC_` environment variable leak challenge, which only worked in development mode.
- Made the padding oracle test deterministic by flipping the entire block, eliminating flaky runs.

## [v2.14.1](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.14.1) - 2026-04-04

### Added

- Added a walkthrough for the "Information Disclosure via API Error Message" vulnerability https://github.com/kOaDT/oss-oopssec-store/issues/62.

### Changed

- Export fields now use an array with checkboxes instead of a comma-separated string, improving "Information Disclosure via API Error Message" vulnerability.
- Bumped `actions/deploy-pages` from 4.0.5 to 5.0.0.

### Fixed

- Fixed incorrect category assignment for the race condition coupon flag (now uses `INSECURE_DESIGN`).
- Removed unused flag type definition.

## [v2.14.0](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.14.0) - 2026-03-28

### Added

- Add a new flag for a race condition vulnerability.

### Fixed

- Removed a stale `screen.png` asset that was incorrectly left in the codebase.

## [v2.13.0](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.13.0) - 2026-03-22

### Added

- Middleware authorization bypass challenge (CVE-2025-29927).
- Support banner after flag capture.
- Educator kit: addition of a kit explaining to teachers, mentors.

### Changed

- Upgraded to Astro 6.
- Node.js bumped to 22.
- Dependency updates.

### Fixed

- Mistral model pinned to `mistral-small-2603`.
- Removed obsolete Astro experimental flag.

## [v2.12.0](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.12.0) - 2026-03-14

### Added

- MCP Malicious Server challenge.

### Changed

- Added business logic test coverage across unit, API, and E2E layers.

### Fixed

- Fixed hydration mismatches.

## [v2.11.0](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.11.0) - 2026-03-13

### Added

- AES-CBC padding oracle vulnerability.

### Changed

- CI pipeline enhancements.
- `actions/checkout` 4.3.1 → 6.0.2.
- `actions/setup-node` 4.4.0 → 6.3.0.

### Security

- Hardened CI workflows.
- Scoped Dependabot to non-vulnerable packages.

## [v2.10.0](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.10.0) - 2026-03-05

### Added

- Profile takeover lab scenarios.
- Docker Hub auto-publish workflow.

### Changed

- Docker setup option in docs and walkthroughs.
- Fixed missing walkthrough slug.

## [v2.9.0](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.9.0) - 2026-03-01

### Added

- Added a new vulnerability flag.

### Changed

- Added a walkthrough for the weak session management vulnerability.
- Improved walkthrough texts, README, and CONTRIBUTING documentation.
- Upgraded Astro to the latest version.

## [v2.8.0](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.8.0) - 2026-02-26

### Added

- Docker support: The application can now be run entirely via Docker and docker-compose, removing the need for a local Node.js installation.
- Insecure password reset flag.

### Changed

- Added a pull request template to standardize contributions.

### Fixed

- Prisma Studio no longer auto-opens a browser during the setup process.
- Improved plaintext password test reliability: Made the assertion more specific to avoid flaky test results.

## [v2.7.0](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.7.0) - 2026-02-22

### Added

- Automated test suite: Added unit tests, API tests (endpoint-based scenarios).
- CI-enforced branch protection: The develop branch has been removed in favor of a single main branch.

### Changed

- Updated documentation in the README and CONTRIBUTING.
- Upgraded GitHub Pages dependencies.

## [v2.6.0](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.6.0) - 2026-02-18

### Added

- XXE injection (supplier order import).
- Image lightbox on blog posts.

### Changed

- Admin dashboard navigation.

## [v2.5.0](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.5.0) - 2026-02-17

### Added

- Added a new Plaintext Password in Logs vulnerability scenario, featuring: https://github.com/kOaDT/oss-oopssec-store/issues/67.
- Global server-side console instrumentation via instrumentation.ts that captures all server output.
- A deliberately left debug statement in the login route that exposes plaintext credentials in logs.

### Changed

- Added the missing walkthrough for the Malicious File Upload / Stored XSS vulnerability to the seed file.
- Added a "Good First Issues" link and a forks badge to the repository.

### Fixed

- Fixed incorrect documentation links for flags displayed in the player dashboard.

## [v2.4.0](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.4.0) - 2026-02-12

### Added

- Introduced a new admin review moderation workflow with customizable display names and an author filtering system.
- Implemented a progressive hints system for CTF flags to help guide players through challenges.

### Changed

- Auth tokens are no longer stored in `localStorage`; they are now handled via HTTP-only cookies with `sameSite:lax`, enabling more accurate simulation of real-world CSRF scenarios.
- Authentication flow redesigned to rely on HTTP-only cookie based JWTs, providing a more realistic browser security model.
- Frontend API layer updated to automatically include credentials in requests.

## [v2.3.1](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.3.1) - 2026-02-07

### Added

- Brute Force vulnerability walkthrough.

### Changed

- Enhanced project documentation.
- Updated README: Added new Repography statistics.
- Fixed BOLA vulnerability documentation.

### Fixed

- Fixed Stored XSS vulnerability in production builds.

## [v2.3.0](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.3.0) - 2026-01-31

### Added

- Added new BOLA (Broken Object Level Authorization) vulnerability.

### Changed

- Enhanced the prompt injection documentation with clearer explanations and more concrete examples.
- Fixed a minor typo in `CONTRIBUTING.md`.

## [v2.2.0](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.2.0) - 2026-01-25

### Added

- Introduced a prompt-injection training challenge in the AI assistant.

## [v2.1.1](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.1.1) - 2026-01-25

### Added

- Added 404 and 500 error pages for improved error handling.
- Introduced PDF invoice generation system with automatic invoice creation on order placement.
- Added directory browsing and PDF viewing functionality on the admin documents page.

### Changed

- Moved documents page to admin section with proper access controls.

### Fixed

- Fixed npm package installation to include building step.
- Fixed typo in Astro homepage command documentation.

## [v2.1.0](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.1.0) - 2026-01-24

### Added

- X-Forwarded-For Header SQL Injection Vulnerability.
- Admin Analytics Page.
- Visitor Tracking Endpoint.

### Changed

- File Upload XSS Attack Chain.
- Exploitation Guides.

## [v2.0.0](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v2.0.0) - 2026-01-23

### Added

- Player Dashboard.
- Persistent Flag Progress Tracking.
- Walkthrough Documentation Site.

### Changed

- Improved documentation site build and configuration to fully support GitHub Pages subpath deployments.
- Refined CI/CD workflows to deploy documentation from the main branch only for production stability.
- Flag Progress Storage Change.

### Fixed

- Fixed Pagefind bundle path handling to ensure search works correctly when deployed under a base path.
- Corrected breadcrumb navigation issues on the walkthroughs website.
- Excluded documentation files from Next.js TypeScript compilation to prevent build errors.

### Security

- XSS Challenge Redesign.
- JWT Vulnerability Realism.

## [v1.11.0](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v1.11.0) - 2026-01-17

### Added

- New Brute Force Vulnerability Challenge.
- Enhanced CSRF Exploit Interface.

### Changed

- News Page Data Leak Enhancement.
- Flag Toast Notification System.
- CSRF Documentation Updates.

## [v1.10.1](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v1.10.1) - 2026-01-16

### Fixed

- Fixed CSRF vulnerability demonstration that stopped working after the migration to token-based authentication.

## [v1.10.0](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v1.10.0) - 2026-01-16

### Added

- Hall of Fame page.
- New flags: Added two new flags for security testing.
- Product search with SQL injection vulnerability.

### Changed

- Weak MD5 hashing vulnerability.
- Replaced ROADMAP.md with GitHub project and updated related links.
- Removed redundant cookie-based authentication code.

## [v1.9.0](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v1.9.0) - 2026-01-13

### Added

- Added malicious file upload vulnerability demonstration with stored XSS.
- Includes admin product image management page with file upload functionality.
- Demonstrates weak Content-Type validation allowing SVG files containing JavaScript.

### Changed

- Redesigned README header with centered layout and updated copy.
- Added ASCII to create-oss-store CLI, setup.sh, and browser console welcome message.
- Updated badges section with additional metrics.

### Fixed

- Fixed writeups link in footer.

## [v1.8.0](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v1.8.0) - 2026-01-12

### Added

- Added difficulty and category metadata to flags, with a corresponding UI to better classify and navigate challenges.
- Introduced a new Information Disclosure API error flag to improve coverage of common security issues.
- Added direct links to documentation pages within the Flag Checker component for faster access to reference material.

### Changed

- Added a new ROADMAP.md and updated README.md and CONTRIBUTING.md to better document project direction and contribution guidelines.

### Fixed

- Fixed missing export of the `User` type from `client-auth`, restoring proper type availability for downstream consumers.

## [v1.7.0](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v1.7.0) - 2026-01-08

### Added

- Added SQL injection flag.
- Added special styling when all flags are found.

### Changed

- Introduced `useAuth` hook and centralized authentication utilities to reduce duplication across components.
- Centralized shared types in `lib/types` for better type management.
- Refactored API layer with a centralized API client (`lib/api.ts`) and typed methods.

### Fixed

- Fixed CLI publish workflow to allow the same version to be published.

## [v1.6.0](https://github.com/kOaDT/oss-oopssec-store/releases/tag/v1.6.0) - 2026-01-07

### Added

- Introduced an SSRF challenge and a reusable flag component.

### Changed

- Improved flag validation feedback, showcase usability, and documentation.

## [1.5.0](https://github.com/kOaDT/oss-oopssec-store/releases/tag/1.5.0) - 2026-01-02

### Added

- Added the `create-oss-store` npm CLI for quick setup.

### Changed

- Improved showcase navigation, README badges, and Git hygiene.

## [1.4.0](https://github.com/kOaDT/oss-oopssec-store/releases/tag/1.4.0) - 2025-12-28

### Added

- Added mass-assignment/parameter-pollution and path-traversal challenges.

### Changed

- Passed the client-side price-manipulation flag through the order confirmation URL.

## [1.3.0](https://github.com/kOaDT/oss-oopssec-store/releases/tag/1.3.0) - 2025-12-22

### Added

- Added IDOR, XSS, and CSRF training challenges.

### Changed

- Removed an unnecessary MD5 reference from the news page.
