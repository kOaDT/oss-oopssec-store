# create-oss-store

Create a new [OSS – OopsSec Store](https://github.com/kOaDT/oss-oopssec-store) instance for web security CTF training.

## Quick Start

```bash
npx create-oss-store my-ctf-lab
cd my-ctf-lab
npm start
```

Then open http://localhost:3000 in your browser and start hunting for flags.

## Options

| Option            | Description                                                          |
| ----------------- | -------------------------------------------------------------------- |
| `[project-name]`  | Target directory (default: `oss-oopssec-store`)                      |
| `--ref <git-ref>` | Tag or branch to install (default: the tag matching the CLI version) |
| `-h`, `--help`    | Show usage                                                           |

Every version of the CLI installs the matching release tag, so the same command
always produces the same lab. Pin it to keep a classroom or a write-up
reproducible:

```bash
npx create-oss-store@2.20.0 my-ctf-lab
```

Use `--ref` to install something else, for instance the latest development state:

```bash
npx create-oss-store my-ctf-lab --ref main
```

## What it does

This CLI will:

- Clone the OSS – OopsSec Store release matching the CLI version
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
