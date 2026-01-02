# create-oss-store

Create a new [OSS – OopsSec Store](https://github.com/kOaDT/oss-oopssec-store) instance for web security CTF training.

## Quick Start

```bash
npx create-oss-store my-ctf-lab
cd my-ctf-lab
npm run dev
```

Then open http://localhost:3000 in your browser and start hunting for flags.

## What it does

This CLI will:

- Clone the OSS – OopsSec Store repository
- Create the `.env` configuration file
- Install all dependencies
- Set up the SQLite database with Prisma
- Seed the database with CTF flags and sample data

## About OSS – OopsSec Store

OSS – OopsSec Store is an open-source, intentionally vulnerable e-commerce application built with Next.js and React. It provides a realistic environment to learn and practice web application security testing, including OWASP Top 10 vulnerabilities, API security flaws, and modern frontend attack vectors.

Designed for penetration testers, security engineers, developers, and cybersecurity students.

For more information, visit the [GitHub repository](https://github.com/kOaDT/oss-oopssec-store).

## License

MIT
