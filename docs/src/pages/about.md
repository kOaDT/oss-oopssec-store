---
layout: ../layouts/AboutLayout.astro
title: "About - OopsSec Store"
---

**OopsSec Store** is an open-source, intentionally vulnerable e-commerce application designed for hands-on web security training. Built with Next.js and React, it provides a realistic environment to learn and practice web application security testing.

This blog documents writeups, walkthroughs, and solutions for the Capture The Flag (CTF) challenges embedded in the platform. Whether you're a penetration tester, security engineer, developer, or cybersecurity student, these guides will help you understand how real-world vulnerabilities manifest in modern single-page applications (SPA) with REST APIs.

## What is OopsSec Store?

OopsSec Store simulates a realistic e-commerce platform containing intentional security flaws including:

- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- Insecure Direct Object References (IDOR)
- JWT attacks
- Path traversal
- And many more OWASP Top 10 vulnerabilities

The goal is simple: hunt for hidden flags, exploit vulnerabilities, and level up your security skills in a safe, legal environment.

## Quick Start

```bash
npx create-oss-store my-ctf-lab
cd my-ctf-lab
npm start
```

Then open [http://localhost:3000](http://localhost:3000) and start hunting flags.

## Who is this for?

- Penetration testers looking for practice targets
- Security engineers wanting to sharpen their skills
- Developers learning secure coding practices
- Cybersecurity students preparing for certifications
- Anyone interested in application security (AppSec)

## Resources

- [GitHub Repository](https://github.com/kOaDT/oss-oopssec-store)
- [NPM Package](https://www.npmjs.com/package/create-oss-store)
- [Contributing Guide](https://github.com/kOaDT/oss-oopssec-store/blob/main/CONTRIBUTING.md)
- [Project Roadmap](https://github.com/users/kOaDT/projects/3)

## Disclaimer

OopsSec Store is intended for educational and authorized security testing purposes only. It contains intentional security vulnerabilities and must never be deployed in a production environment. Use responsibly and only in isolated environments.

## Contributing

OSS – OopsSec Store is released under the MIT License. Contributions from the security community are welcome, whether it's adding new security challenges, extending the application, fixing bugs, or improving documentation.

Found a bug or have an idea? Open a [GitHub Issue](https://github.com/kOaDT/oss-oopssec-store/issues) or submit a [Pull Request](https://github.com/kOaDT/oss-oopssec-store/pulls).
