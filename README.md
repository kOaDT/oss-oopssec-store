# OSS – OopsSec Store

OSS – OopsSec Store is an open-source, deliberately vulnerable e-commerce
application built with Next.js to practice real-world web security
vulnerabilities in a modern web stack.

The project is designed for developers, security engineers, and students who
want to understand how common and advanced web vulnerabilities actually behave
in production-like applications.

This application must never be deployed in a production environment.

---

## Goals

- Provide a realistic e-commerce application with intentional security flaws
- Simulate modern attack scenarios targeting SPA and API-based architectures
- Document each vulnerability as it would appear in a professional security audit
- Serve as a hands-on learning platform for web security and AppSec

---

## Getting Started

### Quick Setup

Clone the repository and run the setup script to install dependencies, initialize the database, and seed it with initial data:

```bash
git clone https://github.com/<your-organization>/oss-oopssec-store.git
cd oss-oopssec-store
npm run setup
```

The setup script will:

- Create a `.env` file with the database configuration
- Install all dependencies
- Generate Prisma Client
- Create and initialize the SQLite database
- Seed the database with sample data
- Run the application on port 3000
- Run Prisma Studio on port 5555

---

## Legal Notice

This project is provided for educational purposes only.

It contains intentional security vulnerabilities and insecure configurations.
The authors assume no responsibility for misuse or deployment in production
environments.

---

## Open Source

OSS – OopsSec Store is released as open source under the MIT License.

Contributions are welcome. Please ensure that any contribution preserves the
educational and intentionally vulnerable nature of the project.
