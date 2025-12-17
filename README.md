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

### Installation

```bash
git clone https://github.com/<your-organization>/oss-oopssec-store.git
cd oss-oopssec-store
npm install
```

### Database Setup

Create a `.env` file in the root directory with the following content:

```env
DATABASE_URL="file:./dev.db"
```

Then initialize the database:

```bash
npm run db:generate
npm run db:push
```

### Running the Application

```bash
npm run dev
```

The application will be available at: `http://localhost:3000`

### Database Commands

- `npm run db:generate` - Generate Prisma Client
- `npm run db:push` - Push schema changes to the database
- `npm run db:migrate` - Create and apply migrations
- `npm run db:studio` - Open Prisma Studio (database GUI)

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
