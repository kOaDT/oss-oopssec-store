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
docker run -p 3000:3000 leogra/oss-oopssec-store
```

---

## Table of Contents

1. [Why OopsSec Store?](#why-oss-oopssec-store)
2. [OWASP Coverage Grid](#owasp-coverage-grid)
3. [Challenge Catalog & Time Estimates](#challenge-catalog--time-estimates)
4. [Syllabus Integration Guide](#syllabus-integration-guide)
5. [Deployment FAQ](#deployment-faq)
6. [Student Report Template](#student-report-template)
7. [Contact & Support](#contact--support)

---

## Why OopsSec Store?

OopsSec Store is the only intentionally vulnerable web application built with **Next.js and React**: the stack your students will actually encounter in production.

|                           | OopsSec Store                    | DVWA            | Juice Shop        |
| ------------------------- | -------------------------------- | --------------- | ----------------- |
| Stack                     | Next.js · React · Prisma         | PHP · MySQL     | Node.js · Angular |
| Setup                     | `npx create-oss-store` (< 1 min) | Manual / Docker | Docker            |
| CTF format with flags     | ✅                               | ❌              | ✅                |
| Walkthroughs included     | ✅                               | Partial (hints) | ❌                |
| Modern API attack vectors | ✅                               | ❌              | Partial           |
| Actively maintained       | ✅                               | ⚠️              | ✅                |
| Hall of Fame for students | ✅                               | ❌              | ❌                |
| Free & open source (MIT)  | ✅                               | ✅              | ✅                |

Each vulnerability hides a flag in the format `OSS{...}`. Walkthroughs are available at [koadt.github.io/oss-oopssec-store](https://koadt.github.io/oss-oopssec-store) (useful for debriefing sessions or when students get stuck.)

---

## OWASP Coverage Grid

OopsSec Store covers the full **OWASP Top 10 (2021)** plus advanced topics relevant to modern web stacks.

| OWASP Category                          | Challenges covered                                                                                                                                                                                                           |
| --------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **A01 - Broken Access Control**         | IDOR (wishlist), BOLA (API), Open Redirect, Session Fixation, Mass Assignment, Path Traversal, Middleware Authorization Bypass (CVE-2025-29927), Business logic bypass via concurrent requests (Race Condition Coupon Abuse) |
| **A02 - Cryptographic Failures**        | Weak MD5 Hashing, Padding Oracle (AES-CBC), Plaintext passwords in logs, Predictable reset token                                                                                                                             |
| **A03 - Injection**                     | SQL Injection (login), Product Search SQLi, Second-Order SQLi, X-Forwarded-For SQLi, XXE (supplier import), Prompt Injection (AI assistant)                                                                                  |
| **A04 - Insecure Design**               | Insecure password reset flow, Client-side price manipulation, Brute force (no rate limiting), Race Condition Coupon Abuse                                                                                                    |
| **A05 - Security Misconfiguration**     | Public environment variable exposure, Exposed `.env` via path traversal, Information disclosure via API errors                                                                                                               |
| **A06 - Vulnerable Components**         | React Server Components RCE (React2Shell / CVE-2025-55182)                                                                                                                                                                   |
| **A07 - Auth & Session Failures**       | Weak JWT secret, Session fixation, Brute force (no rate limiting), Weak session management                                                                                                                                   |
| **A08 - Software & Data Integrity**     | MCP server poisoning, Malicious tool responses, CSRF                                                                                                                                                                         |
| **A09 - Logging & Monitoring Failures** | Plaintext password logging, Information disclosure via API errors                                                                                                                                                            |
| **A10 - SSRF**                          | Server-Side Request Forgery via upload feature                                                                                                                                                                               |
| **Beyond OWASP Top 10**                 | Self-XSS (profile injection), Self-XSS + CSRF chaining (profile takeover), Stored XSS (SVG upload), MCP agent manipulation                                                                                                   |

---

## Challenge Catalog & Time Estimates

Difficulty: 🟢 Beginner · 🟡 Intermediate · 🔴 Advanced

| #   | Challenge                                        | Category               | Difficulty | Est. time  |
| --- | ------------------------------------------------ | ---------------------- | ---------- | ---------- |
| 1   | Public Environment Variable Exposure             | Information Disclosure | 🟢         | 15–20 min  |
| 2   | Information Disclosure via API Errors            | Information Disclosure | 🟢         | 15–20 min  |
| 3   | IDOR - Private Wishlist Access                   | Broken Access Control  | 🟢         | 20–30 min  |
| 4   | Open Redirect via Login Page                     | Input Validation       | 🟢         | 20–30 min  |
| 5   | Stored XSS via Product Review                    | Injection              | 🟢         | 30–45 min  |
| 6   | Self-XSS - Profile Bio Injection                 | Injection              | 🟢         | 20–30 min  |
| 7   | SQL Injection (Login)                            | Injection              | 🟡         | 30–45 min  |
| 8   | Product Search SQL Injection                     | Injection              | 🟡         | 30–45 min  |
| 9   | Weak JWT Secret                                  | Authentication         | 🟡         | 45–60 min  |
| 10  | Client-Side Price Manipulation                   | Input Validation       | 🟡         | 30–45 min  |
| 11  | Weak MD5 Hashing                                 | Cryptographic          | 🟡         | 30–45 min  |
| 12  | Cross-Site Request Forgery (CSRF)                | Request Forgery        | 🟡         | 45–60 min  |
| 13  | Mass Assignment / Parameter Pollution            | Input Validation       | 🟡         | 45–60 min  |
| 14  | Path Traversal                                   | Input Validation       | 🟡         | 30–45 min  |
| 15  | Server-Side Request Forgery (SSRF)               | Request Forgery        | 🟡         | 45–60 min  |
| 16  | Session Fixation & Weak Session Management       | Authentication         | 🟡         | 60–90 min  |
| 17  | Brute Force - No Rate Limiting                   | Authentication         | 🟡         | 30–45 min  |
| 18  | Insecure Password Reset                          | Authentication         | 🟡         | 45–60 min  |
| 19  | Broken Object Level Authorization (BOLA)         | Authorization          | 🟡         | 45–60 min  |
| 20  | Plaintext Password in Server Logs                | Information Disclosure | 🟡         | 30 min     |
| 21  | Prompt Injection - AI Support Assistant          | Injection              | 🟡         | 60–90 min  |
| 22  | Middleware Authorization Bypass (CVE-2025-29927) | Authorization          | 🟡         | 30–45 min  |
| 23  | Second-Order SQL Injection                       | Injection              | 🔴         | 60–90 min  |
| 24  | XXE - Supplier Import Endpoint                   | Injection              | 🔴         | 45–60 min  |
| 25  | SVG Upload - Stored XSS                          | Injection              | 🔴         | 45–60 min  |
| 26  | X-Forwarded-For SQL Injection                    | Injection              | 🔴         | 60–90 min  |
| 27  | CSRF + Self-XSS Chain - Profile Takeover         | Request Forgery        | 🔴         | 90–120 min |
| 28  | Padding Oracle - AES-CBC Token Forgery           | Cryptographic          | 🔴         | 90–120 min |
| 29  | MCP Server Poisoning - Agent Manipulation        | Injection              | 🔴         | 90–120 min |
| 30  | React2Shell - RSC RCE (CVE-2025-55182)           | RCE                    | 🔴         | 120+ min   |
| 31  | Race Condition — Coupon Abuse                    | Business Logic         | 🔴         | 45–90 min  |

**Total estimated time:** 31–45 hours for the full curriculum depending on student level. You don't need to cover everything. Pick the challenges that match your course objectives and time constraints.

---

## Syllabus Integration Guide

### Option A - One-week intensive (bootcamp)

Designed for a 5-day security bootcamp with 3–4 hours of lab time per day.

| Day   | Focus                          | Challenges                                                                                                             |
| ----- | ------------------------------ | ---------------------------------------------------------------------------------------------------------------------- |
| Day 1 | Recon & injection fundamentals | Public Env Variable, Info Disclosure API, SQL Injection (login), Product Search SQLi, X-Forwarded-For SQLi             |
| Day 2 | Client-side attacks            | Stored XSS (review), Self-XSS (profile), SVG Upload XSS, CSRF, CSRF + Self-XSS chain                                   |
| Day 3 | Auth & access control          | IDOR, BOLA, Open Redirect, Weak JWT, Session Fixation, Brute Force, Password Reset, Middleware Bypass (CVE-2025-29927) |
| Day 4 | Crypto, data & server-side     | Weak MD5, Padding Oracle, Plaintext Logs, Path Traversal, SSRF, Client-Side Price Manipulation, Mass Assignment        |
| Day 5 | Advanced & AI security         | Second-Order SQLi, XXE, Prompt Injection, MCP Poisoning, React2Shell RCE, Race Condition Coupon Abuse                  |

**Debrief format:** After each session, share the walkthrough URL for each challenge and run a 15-min group debrief. Encourage students to compare their approach with the official walkthrough.

---

### Option B - Semester module (university)

Designed to complement a web security or application security course over 6–8 weeks, with one 2-hour lab session per week.

| Week | Topic                             | Challenges                                                                                                    | Learning outcomes                                     |
| ---- | --------------------------------- | ------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------- |
| 1    | Lab setup & recon                 | Public Env Variable, Info Disclosure API                                                                      | Understand the app architecture and attack surface    |
| 2    | SQL Injection                     | SQL Injection (login), Product Search SQLi, X-Forwarded-For SQLi                                              | Identify and exploit injection in modern ORMs         |
| 3    | XSS & client-side attacks         | Stored XSS, Self-XSS (profile), SVG Upload XSS                                                                | Understand DOM context and stored payload execution   |
| 4    | Access control & input validation | IDOR, BOLA, Open Redirect, Path Traversal, Client-Side Price Manipulation, Middleware Bypass (CVE-2025-29927) | Enumerate and exploit broken access controls          |
| 5    | Auth & session management         | Weak JWT, Session Fixation, Brute Force, Password Reset, Mass Assignment                                      | Analyze authentication flaws in real flows            |
| 6    | Cryptographic & logging failures  | Weak MD5, Padding Oracle, Plaintext Logs                                                                      | Exploit weak crypto implementations                   |
| 7    | Request forgery & chaining        | CSRF, SSRF, CSRF + Self-XSS chain                                                                             | Chain low-severity bugs into critical exploits        |
| 8    | Advanced injection & AI security  | Second-Order SQLi, XXE, Prompt Injection, MCP Poisoning                                                       | Understand advanced injection and AI attack surfaces  |
| 9    | Business logic & race conditions  | Client-Side Price Manipulation, Race Condition Coupon Abuse                                                   | Exploit non-atomic state transitions and TOCTOU flaws |

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
Challenges 1–6 (recon & basics) → 7–8 (SQLi) → 12 (CSRF) → 14 (Path Traversal) → 21 (Prompt Injection). Focus on the "How to Fix" section of each walkthrough.

**Recommended path for junior pentesters** (focus on technique):
Full catalog in order of difficulty. Target: complete all 30 challenges in 4–5 weeks of part-time practice.

---

## Deployment FAQ

### Can I run this in a classroom with no internet access?

Yes. Both the local Node.js and Docker setups are fully self-contained. No external network calls are required after initial setup.

```bash
# Pre-pull the Docker image on your network
docker pull leogra/oss-oopssec-store

# Students run locally with no internet
docker run -p 3000:3000 leogra/oss-oopssec-store
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
| Node.js    | Node 18+, npm                    |
| Docker     | Docker Desktop or Docker Engine  |
| Disk space | ~500 MB                          |
| RAM        | 512 MB minimum, 1 GB recommended |

### Can I contribute new challenges for my course?

Yes, contributions are welcome. See [CONTRIBUTING.md](https://github.com/kOaDT/oss-oopssec-store/blob/main/CONTRIBUTING.md). New challenges should include a flag in `seed.ts` and a markdown walkthrough in `content/vulnerabilities/`.

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

_Last updated: March 2026. New challenges may have been added since this guide was written/updated._

_OSS OopsSec Store is MIT-licensed. Free to use, adapt, and share._
_Do not deploy in production environments. For educational use only._
