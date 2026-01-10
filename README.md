# OSS – OopsSec Store | Vulnerable Web Application for Security Training

[![GitHub license](https://img.shields.io/github/license/kOaDT/oss-oopssec-store?style=flat-square)](https://github.com/kOaDT/oss-oopssec-store/blob/main/LICENSE)
[![GitHub release](https://img.shields.io/github/v/release/kOaDT/oss-oopssec-store?style=flat-square)](https://github.com/kOaDT/oss-oopssec-store/releases)
[![npm version](https://img.shields.io/npm/v/create-oss-store?style=flat-square)](https://www.npmjs.com/package/create-oss-store)
[![GitHub stars](https://img.shields.io/github/stars/kOaDT/oss-oopssec-store?style=social)](https://github.com/kOaDT/oss-oopssec-store/stargazers)

A self-hosted Capture The Flag platform for web security training. Run `npx create-oss-store` and start hunting for flags. Each vulnerability is documented and comes with a hidden flag to discover.

![OSS – OopsSec Store](screen.png)

---

OSS – OopsSec Store is an open-source, intentionally vulnerable e-commerce application built with Next.js and React. It provides a realistic environment to learn and practice web application security testing, including OWASP Top 10 vulnerabilities, API security flaws, and modern frontend attack vectors.

Designed for penetration testers, security engineers, developers, and cybersecurity students, this project demonstrates how real-world vulnerabilities manifest in production-like single-page applications (SPA) with REST APIs.

**Warning:** This application contains intentional security flaws and must never be deployed in a production environment.

---

## Features

- Realistic e-commerce application with intentional security vulnerabilities (XSS, CSRF, IDOR, JWT attacks, path traversal, and more)
- Modern tech stack: Next.js, React, Prisma
- API security testing environment with documented attack vectors
- Capture The Flag (CTF) challenges with hidden flags to discover
- Comprehensive vulnerability documentation for learning and training
- Suitable for security awareness training, penetration testing practice, and AppSec education

---

## Recent activity [![Time period](https://images.repography.com/103508692/kOaDT/oss-oopssec-store/recent-activity/Q7MububoYUVlm99MQWYW12szb_gGlehkuutaTn9WlA4/8o02KXC0HvWi_KfBHD6iD-qSBHSu0s9Y_rns1fvWSjg_badge.svg)](https://repography.com)

[![Timeline graph](https://images.repography.com/103508692/kOaDT/oss-oopssec-store/recent-activity/Q7MububoYUVlm99MQWYW12szb_gGlehkuutaTn9WlA4/8o02KXC0HvWi_KfBHD6iD-qSBHSu0s9Y_rns1fvWSjg_timeline.svg)](https://github.com/kOaDT/oss-oopssec-store/commits)
[![Trending topics](https://images.repography.com/103508692/kOaDT/oss-oopssec-store/recent-activity/Q7MububoYUVlm99MQWYW12szb_gGlehkuutaTn9WlA4/8o02KXC0HvWi_KfBHD6iD-qSBHSu0s9Y_rns1fvWSjg_words.svg)](https://github.com/kOaDT/oss-oopssec-store/commits)

---

## Installation

### Quick Start

```bash
npx create-oss-store my-ctf-lab
cd my-ctf-lab
npm run dev
```

Then open http://localhost:3000 in your browser.

### Manual Setup

Alternatively, clone the repository and run the setup script:

```bash
git clone https://github.com/kOaDT/oss-oopssec-store.git
cd oss-oopssec-store
npm run setup
```

The setup script will create the `.env` file, install dependencies, initialize the SQLite database, seed it with CTF flags, and start the application on port 3000.

---

## Project Structure

[![Structure](https://images.repography.com/103508692/kOaDT/oss-oopssec-store/structure/Q7MububoYUVlm99MQWYW12szb_gGlehkuutaTn9WlA4/xqocpGlYz1v1FH126K5mqp7WjOcy1VH9pbA-EuINusA_table.svg)](https://github.com/kOaDT/oss-oopssec-store)

| Folder                     | Description                                                              |
| -------------------------- | ------------------------------------------------------------------------ |
| `app/`                     | Next.js App Router – pages, API routes, and React components             |
| `app/api/`                 | REST API endpoints (auth, cart, orders, products, flags, etc.)           |
| `app/components/`          | Reusable React UI components (Header, Footer, ProductCard, etc.)         |
| `app/vulnerabilities/`     | Pages documenting each security vulnerability                            |
| `content/vulnerabilities/` | Markdown files describing vulnerabilities, attack vectors, and solutions |
| `lib/`                     | Shared utilities: database client, authentication, API helpers, types    |
| `prisma/`                  | Database schema, migrations, and seed script with CTF flags              |
| `public/`                  | Static assets and exploit payloads (e.g., CSRF attack demo)              |
| `hooks/`                   | Custom React hooks (authentication, etc.)                                |
| `scripts/`                 | Setup and automation scripts                                             |
| `docs/`                    | Static documentation site                                                |
| `packages/`                | NPM package `create-oss-store` for quick project scaffolding             |

---

## Disclaimer

This project is intended for educational and authorized security testing purposes only.

It contains intentional security vulnerabilities and insecure configurations. The authors assume no responsibility for any misuse, damage, or unauthorized access resulting from the use of this software. Use responsibly and only in isolated environments.

---

## Contributing

OSS – OopsSec Store is released under the MIT License. Contributions from the security community are welcome.

Ways to contribute:

- **Add new security challenges**
- **Extend the application**
- **Report and fix bugs**
- **Improve documentation**

Looking for ideas? Check out our [ROADMAP.md](ROADMAP.md) for planned features and vulnerabilities you can help implement.

For issues or suggestions, please open a [GitHub Issue](https://github.com/kOaDT/oss-oopssec-store/issues).

For contribution guidelines, see [CONTRIBUTING.md](CONTRIBUTING.md).

<!-- [![Issue status graph](https://images.repography.com/103508692/kOaDT/oss-oopssec-store/recent-activity/Q7MububoYUVlm99MQWYW12szb_gGlehkuutaTn9WlA4/8o02KXC0HvWi_KfBHD6iD-qSBHSu0s9Y_rns1fvWSjg_issues.svg)](https://github.com/kOaDT/oss-oopssec-store/issues)
[![Pull request status graph](https://images.repography.com/103508692/kOaDT/oss-oopssec-store/recent-activity/Q7MububoYUVlm99MQWYW12szb_gGlehkuutaTn9WlA4/8o02KXC0HvWi_KfBHD6iD-qSBHSu0s9Y_rns1fvWSjg_prs.svg)](https://github.com/kOaDT/oss-oopssec-store/pulls) -->
<!-- [![Activity map](https://images.repography.com/103508692/kOaDT/oss-oopssec-store/recent-activity/Q7MububoYUVlm99MQWYW12szb_gGlehkuutaTn9WlA4/8o02KXC0HvWi_KfBHD6iD-qSBHSu0s9Y_rns1fvWSjg_map.svg)](https://github.com/kOaDT/oss-oopssec-store/commits) -->
