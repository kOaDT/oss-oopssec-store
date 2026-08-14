# Educator Kit - OSS OopsSec Store

> A ready-to-use guide for instructors, bootcamp trainers, CTF organizers, and security team leads who want to integrate OSS OopsSec Store into their curriculum or training sessions.

**Quick start for your students:**

```bash
npx create-oss-store my-lab
cd my-lab && npm start
# → http://localhost:3000
```

Or with Docker (no Node.js required):

```bash
docker run -p 127.0.0.1:3000:3000 leogra/oss-oopssec-store
```

Point your students to the [Roadmap](https://koadt.github.io/oss-oopssec-store/roadmap) as their entry point. It lays out all 36 challenges in a visual learning path, with chapters ordered from easy to hard, and recommends a self-guided approach (try the challenge first, then read the walkthrough).

---

## Table of Contents

1. [Why OopsSec Store?](#why-oopssec-store)
2. [OWASP Coverage Grid](#owasp-coverage-grid)
3. [Challenge Catalog & Time Estimates](#challenge-catalog--time-estimates)
4. [Syllabus Integration Guide](#syllabus-integration-guide)
5. [Deployment FAQ](#deployment-faq)
6. [Student Report Template](#student-report-template)
7. [Contact & Support](#contact--support)

---

## Why OopsSec Store?

OopsSec Store is the only intentionally vulnerable web application built with **Next.js and React**: the stack your students will actually encounter in production. It also treats the AI-era attack surface — prompt injection, MCP tool poisoning, AI coding-agent backdoors, supply-chain attack chains — as first-class challenges, not add-ons.

For a feature-by-feature comparison with Juice Shop and DVWA, see the [comparison table in the README](https://github.com/kOaDT/oss-oopssec-store#why-oopssec-store).

Each vulnerability hides a flag in the format `OSS{...}`. Walkthroughs are available at [koadt.github.io/oss-oopssec-store](https://koadt.github.io/oss-oopssec-store) (useful for debriefing sessions or when students get stuck.)

---

## OWASP Coverage Grid

OopsSec Store covers the full **OWASP Top 10 (2025)** plus advanced topics relevant to modern web stacks.

| OWASP Category                                  | Challenges covered                                                                                                                                                                         |
| ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **A01 - Broken Access Control**                 | IDOR (orders), BOLA (wishlist), BFLA (live stream hijack), Open Redirect, Path Traversal, Middleware Authorization Bypass (CVE-2025-29927), CSRF, CSRF + Self-XSS chain (profile takeover) |
| **A02 - Security Misconfiguration**             | Public environment variable exposure, Information disclosure via API errors, XXE (supplier import)                                                                                         |
| **A03 - Software Supply Chain Failures**        | npm Typosquat → AI Rules File Backdoor chain (typosquatted package drops a malicious Cursor/Claude rules file with a hidden prompt-injection payload that steers the dev's AI agent)       |
| **A04 - Cryptographic Failures**                | Weak JWT secret, Weak MD5 Hashing, Padding Oracle (AES-CBC), Insecure Randomness (gift card code generation), JWT Algorithm Confusion (RS256 → HS256 on the Partner API)                   |
| **A05 - Injection**                             | Stored XSS (product reviews), Self-XSS (profile injection), SQL Injection (login), Product Search SQLi, Second-Order SQLi, X-Forwarded-For SQLi, Prompt Injection, MCP Server Poisoning    |
| **A06 - Insecure Design**                       | Client-side price manipulation, Stored XSS via SVG upload, Race Condition Coupon Abuse                                                                                                     |
| **A07 - Authentication Failures**               | Session fixation & weak session management, Brute force (no rate limiting), Insecure password reset, AI Rules File Backdoor (hardcoded magic-header auth bypass on hidden diag endpoint)   |
| **A08 - Software or Data Integrity Failures**   | React2Shell - RSC RCE (CVE-2025-55182), Mass Assignment / Parameter Pollution                                                                                                              |
| **A09 - Security Logging & Alerting Failures**  | Plaintext password logging                                                                                                                                                                 |
| **A10 - Mishandling of Exceptional Conditions** | _No challenge currently maps directly to A10 — contributions welcome._                                                                                                                     |

> **Note on SSRF:** The Server-Side Request Forgery challenge is tagged `A10:2021` since SSRF was removed as a standalone category in the 2025 release — it is now implicitly covered under A01 Broken Access Control.

---

## Challenge Catalog & Time Estimates

A visual version of this catalog is available as the [Roadmap](https://koadt.github.io/oss-oopssec-store/roadmap) on the docs site, grouped into 11 thematic chapters.

Building a tool around the curriculum? The same data is published as JSON at [`challenges.json`](https://koadt.github.io/oss-oopssec-store/challenges.json) — every column of the table below (number, title, chapter, category, difficulty, estimated minutes) plus prerequisites and the walkthrough URL, regenerated on every docs deploy. Each entry carries a `slug` that joins with the app's `/api/flags`; it is unique across the feed. Note that `walkthrough.slug` is **not** — a chained challenge shares its write-up with the challenge it builds on (14 and 16, 34 and 35), so deduplicating on that field would drop entries.

Difficulty: 🟢 Beginner · 🟡 Intermediate · 🔴 Advanced

The Category column uses the same vocabulary as the app's `FlagCategory` enum (`AUTHORIZATION`, `INSECURE_DESIGN`, `REMOTE_CODE_EXECUTION`…), spelled out here for readability, so the table, the JSON feed and `/api/flags` all agree.

| #   | Challenge                                                | Chapter                     | Category               | Difficulty | Est. time  |
| --- | -------------------------------------------------------- | --------------------------- | ---------------------- | ---------- | ---------- |
| 1   | Public env variable leak                                 | Reconnaissance & Disclosure | Information Disclosure | 🟢         | 15–20 min  |
| 2   | Information disclosure via API errors                    | Reconnaissance & Disclosure | Information Disclosure | 🟢         | 15–20 min  |
| 3   | Plaintext passwords in logs                              | Reconnaissance & Disclosure | Information Disclosure | 🟡         | 30 min     |
| 4   | Insecure Direct Object Reference (IDOR)                  | Broken Access Control       | Authorization          | 🟢         | 20–30 min  |
| 5   | Open redirect to login bypass                            | Broken Access Control       | Input Validation       | 🟢         | 20–30 min  |
| 6   | Broken Object Level Authorization (BOLA)                 | Broken Access Control       | Authorization          | 🟡         | 45–60 min  |
| 7   | Broken Function Level Authorization (live stream hijack) | Broken Access Control       | Authorization          | 🟡         | 45–60 min  |
| 8   | Path traversal in document API                           | Broken Access Control       | Input Validation       | 🟡         | 30–45 min  |
| 9   | Client-side price manipulation                           | Trusting the Client         | Input Validation       | 🟡         | 30–45 min  |
| 10  | Mass assignment to admin role                            | Trusting the Client         | Input Validation       | 🟡         | 45–60 min  |
| 11  | Middleware bypass (CVE-2025-29927)                       | Trusting the Client         | Authorization          | 🟡         | 30–45 min  |
| 12  | Race condition coupon abuse                              | Trusting the Client         | Insecure Design        | 🔴         | 45–90 min  |
| 13  | Stored XSS in product reviews                            | Cross-Site Attacks          | Injection              | 🟢         | 30–45 min  |
| 14  | Self-XSS in profile bio                                  | Cross-Site Attacks          | Injection              | 🟢         | 20–30 min  |
| 15  | CSRF on admin order update                               | Cross-Site Attacks          | Request Forgery        | 🟡         | 45–60 min  |
| 16  | CSRF + Self-XSS profile takeover                         | Cross-Site Attacks          | Request Forgery        | 🔴         | 90–120 min |
| 17  | SQL injection in order search                            | SQL Injection Deep Dive     | Injection              | 🟡         | 30–45 min  |
| 18  | Product search SQLi                                      | SQL Injection Deep Dive     | Injection              | 🟡         | 30–45 min  |
| 19  | X-Forwarded-For SQLi                                     | SQL Injection Deep Dive     | Injection              | 🔴         | 60–90 min  |
| 20  | Second-order SQL injection                               | SQL Injection Deep Dive     | Injection              | 🔴         | 60–90 min  |
| 21  | Malicious file upload (SVG XSS)                          | Parsers Behaving Badly      | Injection              | 🔴         | 45–60 min  |
| 22  | XXE in supplier order import                             | Parsers Behaving Badly      | Injection              | 🔴         | 45–60 min  |
| 23  | Weak JWT secret                                          | Authentication Failures     | Authentication         | 🟡         | 45–60 min  |
| 24  | Brute force, no rate limiting                            | Authentication Failures     | Authentication         | 🟡         | 30–45 min  |
| 25  | Session fixation                                         | Authentication Failures     | Authentication         | 🟡         | 60–90 min  |
| 26  | Insecure password reset                                  | Authentication Failures     | Authentication         | 🟡         | 45–60 min  |
| 27  | SSRF internal page access                                | Server-Side Request Forgery | Request Forgery        | 🟡         | 45–60 min  |
| 28  | Weak MD5 password hashing                                | Cryptography Done Wrong     | Cryptographic          | 🟡         | 30–45 min  |
| 29  | Insecure randomness in gift cards                        | Cryptography Done Wrong     | Cryptographic          | 🟡         | 45–60 min  |
| 30  | AES-CBC padding oracle                                   | Cryptography Done Wrong     | Cryptographic          | 🔴         | 90–120 min |
| 31  | JWT algorithm confusion (partner API)                    | Cryptography Done Wrong     | Cryptographic          | 🔴         | 90–120 min |
| 32  | Prompt injection in AI assistant                         | AI & LLM Security           | Injection              | 🟡         | 60–90 min  |
| 33  | MCP malicious server                                     | AI & LLM Security           | Injection              | 🔴         | 90–120 min |
| 34  | npm typosquat                                            | Supply Chain & Framework    | Supply Chain           | 🔴         | 60–90 min  |
| 35  | AI rules file backdoor                                   | Supply Chain & Framework    | Supply Chain           | 🟡         | 20–30 min  |
| 36  | react2shell (CVE-2025-55182)                             | Supply Chain & Framework    | Remote Code Execution  | 🔴         | 120+ min   |

**Total estimated time:** 27–38 hours for the full curriculum depending on student level. Challenges 34 and 35 are chained — once the chain is started for flag #34, flag #35 follows in a few minutes.
You don't need to cover everything. Pick the challenges that match your course objectives and time constraints.

---

## Syllabus Integration Guide

### Option A - One-week intensive (bootcamp)

Designed for a 5-day security bootcamp with 3–4 hours of lab time per day.

| Day   | Focus                          | Challenges                                                                                                                                                                |
| ----- | ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Day 1 | Recon & injection fundamentals | Public Env Variable, Info Disclosure API, SQL Injection (login), Product Search SQLi, X-Forwarded-For SQLi                                                                |
| Day 2 | Client-side attacks            | Stored XSS (review), Self-XSS (profile), SVG Upload XSS, CSRF, CSRF + Self-XSS chain                                                                                      |
| Day 3 | Auth & access control          | IDOR, BOLA, Open Redirect, Weak JWT, Session Fixation, Brute Force, Password Reset, Middleware Bypass (CVE-2025-29927)                                                    |
| Day 4 | Crypto, data & server-side     | Weak MD5, Padding Oracle, JWT Algorithm Confusion, Insecure Randomness (gift card), Plaintext Logs, Path Traversal, SSRF, Client-Side Price Manipulation, Mass Assignment |
| Day 5 | Advanced, supply chain & AI    | Second-Order SQLi, XXE, Prompt Injection, MCP Poisoning, React2Shell RCE, Race Condition Coupon Abuse, npm Typosquat → AI Rules File Backdoor                             |

**Debrief format:** After each session, share the walkthrough URL for each challenge and run a 15-min group debrief. Encourage students to compare their approach with the official walkthrough.

---

### Option B - Semester module (university)

Designed to complement a web security or application security course over 6–10 weeks, with one 2-hour lab session per week.

| Week | Topic                             | Challenges                                                                                                    | Learning outcomes                                                     |
| ---- | --------------------------------- | ------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| 1    | Lab setup & recon                 | Public Env Variable, Info Disclosure API                                                                      | Understand the app architecture and attack surface                    |
| 2    | SQL Injection                     | SQL Injection (login), Product Search SQLi, X-Forwarded-For SQLi                                              | Identify and exploit injection in modern ORMs                         |
| 3    | XSS & client-side attacks         | Stored XSS, Self-XSS (profile), SVG Upload XSS                                                                | Understand DOM context and stored payload execution                   |
| 4    | Access control & input validation | IDOR, BOLA, Open Redirect, Path Traversal, Client-Side Price Manipulation, Middleware Bypass (CVE-2025-29927) | Enumerate and exploit broken access controls                          |
| 5    | Auth & session management         | Weak JWT, Session Fixation, Brute Force, Password Reset, Mass Assignment                                      | Analyze authentication flaws in real flows                            |
| 6    | Cryptographic & logging failures  | Weak MD5, Padding Oracle, JWT Algorithm Confusion, Insecure Randomness (gift card), Plaintext Logs            | Exploit weak crypto implementations                                   |
| 7    | Request forgery & chaining        | CSRF, SSRF, CSRF + Self-XSS chain                                                                             | Chain low-severity bugs into critical exploits                        |
| 8    | Advanced injection & AI security  | Second-Order SQLi, XXE, Prompt Injection, MCP Poisoning                                                       | Understand advanced injection and AI attack surfaces                  |
| 9    | Business logic & race conditions  | Client-Side Price Manipulation, Race Condition Coupon Abuse                                                   | Exploit non-atomic state transitions and TOCTOU flaws                 |
| 10   | Supply chain & AI tooling risk    | npm Typosquat, AI Rules File Backdoor                                                                         | Recognize supply-chain attack chains and AI-tooling poisoning vectors |

**Assessment:** Use the [Student Report Template](#student-report-template) as a graded deliverable for each challenge.

---

### Option C - CTF event (half-day or full-day)

Designed for competitive CTF events with 10–30 participants.

**Setup:** Deploy one shared instance with Docker for the event, or have each participant run their own local instance.

```bash
# Shared instance (for organizers)
git clone https://github.com/kOaDT/oss-oopssec-store.git
cd oss-oopssec-store
docker compose up -d

# Per-participant instance
npx create-oss-store my-lab && cd my-lab && npm start
```

**Scoring suggestion:**

- 🟢 Beginner challenges: 100 pts each
- 🟡 Intermediate challenges: 250 pts each
- 🔴 Advanced challenges: 500 pts each

**Hall of Fame:** Participants who find all flags can submit a PR to the [Hall of Fame](https://github.com/kOaDT/oss-oopssec-store/blob/main/hall-of-fame/data.json) to have their profile listed in the app.

---

### Option D - Security team internal training

Designed for pentesters or developers onboarding to a security-aware team.

**Recommended path for developers** (focus on understanding, not exploitation):
Public Env Variable, Info Disclosure API, IDOR, Open Redirect, Stored XSS, Self-XSS (recon & basics) → SQL Injection (login), Product Search SQLi → CSRF → Path Traversal → Prompt Injection. Focus on the "How to Fix" section of each walkthrough.

**Recommended path for junior pentesters** (focus on technique):
Full catalog in roadmap order. Target: complete all 36 challenges in 4–5 weeks of part-time practice.

---

## Deployment FAQ

### Can I run this in a classroom with no internet access?

Yes. Both the local Node.js and Docker setups are fully self-contained. No external network calls are required after initial setup.

```bash
# Pre-pull the Docker image on your network
docker pull leogra/oss-oopssec-store

# Students run locally with no internet
docker run -p 127.0.0.1:3000:3000 leogra/oss-oopssec-store
```

### Can multiple students share one instance?

It's not recommended. Each student should run their own local instance. Shared instances can cause flag collisions (a student capturing a flag that another already submitted) and pollute the database state.

Exception: for CTF events where competition is the goal, a shared instance is fine.

### How do I reset the database between sessions?

```bash
# Node.js setup
npm run setup   # Re-seeds the database from scratch

# Docker setup
npm run docker:reset   # Wipes all data and restarts fresh
```

### Is it safe to run on a school or company network?

**No.** OopsSec Store must only be run in isolated environments (local machine or air-gapped VM). It contains intentional security flaws and must never be exposed to a production network or the internet.

Recommended setup for classrooms: each student runs the app on their own machine via `localhost`. No shared network exposure needed.

### What are the system requirements?

| Setup      | Requirements                     |
| ---------- | -------------------------------- |
| Node.js    | Node 20+, npm                    |
| Docker     | Docker Desktop or Docker Engine  |
| Disk space | ~500 MB                          |
| RAM        | 512 MB minimum, 1 GB recommended |

### Can I contribute new challenges for my course?

Yes, contributions are welcome. See the "Adding a challenge" checklist in [CONTRIBUTING.md](https://github.com/kOaDT/oss-oopssec-store/blob/main/CONTRIBUTING.md#adding-a-challenge). A new challenge needs a flag in `prisma/flags.ts`, three hints, an exploitable code path, a reference doc in `content/vulnerabilities/`, regression tests, a walkthrough on the docs site and an entry on the roadmap. `npm run test:unit` tells you what is still missing.

---

## Student Report Template

Use this template as a graded deliverable for each challenge. Students should complete one report per vulnerability exploited.

---

```markdown
# Vulnerability Report - [Challenge Name]

**Student name:** **\*\***\_\_\_**\*\***
**Date:** **\*\***\_\_\_**\*\***
**Challenge difficulty:** 🟢 Beginner / 🟡 Intermediate / 🔴 Advanced

---

## 1. Vulnerability Summary

> In 2–3 sentences, describe the vulnerability in your own words.
> What is it? Where is it located in the application?

[Your answer here]

---

## 2. Steps to Reproduce

> List the exact steps you followed to exploit the vulnerability.
> Be precise enough that someone else could reproduce it.

1.
2.
3.

---

## 3. Proof of Exploitation

> Paste the flag you captured, and include a screenshot or HTTP request
> showing the successful exploit.

**Flag:** `OSS{...}`

**Evidence:**
[Screenshot / HTTP request / payload]

---

## 4. Root Cause Analysis

> Why does this vulnerability exist?
> What insecure code pattern or configuration makes it possible?

[Your answer here]

---

## 5. Remediation

> How would you fix this vulnerability?
> Reference OWASP guidance or best practices where relevant.

[Your answer here]

---

## 6. OWASP Classification

> Which OWASP Top 10 category does this vulnerability belong to?
> Justify your answer.

**Category:** A0X - [Name]
**Justification:** [Your answer here]

---

## 7. Reflection

> What did you learn from this challenge?
> Was anything surprising or harder than expected?

[Your answer here]
```

---

## Contact & Support

- **Issues & bug reports:** [github.com/kOaDT/oss-oopssec-store/issues](https://github.com/kOaDT/oss-oopssec-store/issues)
- **Discussions & questions:** [github.com/kOaDT/oss-oopssec-store/discussions](https://github.com/kOaDT/oss-oopssec-store/discussions)
- **Walkthroughs:** [koadt.github.io/oss-oopssec-store](https://koadt.github.io/oss-oopssec-store)
- **Email:** [koadt@proton.me](mailto:koadt@proton.me)

If you use OopsSec Store in your course or event, I'd love to hear about it. Open a Discussion or send an email. Feedback from educators directly shapes the roadmap.

---

_Last updated: May 2026. New challenges may have been added since this guide was written/updated._

_OSS OopsSec Store is MIT-licensed. Free to use, adapt, and share._
_Do not deploy in production environments. For educational use only._
