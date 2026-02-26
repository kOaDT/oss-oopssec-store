# OSS – OopsSec Store

Intentionally vulnerable e-commerce web application for security training and Capture The Flag (CTF) challenges.

> **⚠️ CRITICAL:** This application contains intentional security flaws. Never deploy in production. Vulnerabilities are features, not bugs.

## Tech Stack

| Layer    | Technology                                                              |
| -------- | ----------------------------------------------------------------------- |
| Frontend | Next.js 16.0.6 (App Router), React 19.2.0, TypeScript 5, Tailwind CSS 4 |
| Backend  | Next.js API Routes, SQLite + Prisma ORM 6.19.1                          |
| Auth     | JWT tokens (intentionally weak implementation)                          |
| Font     | Poppins (Google Fonts)                                                  |
| Markdown | react-markdown + remark-gfm                                             |

## Project Structure

```
app/
├── api/                    # REST API endpoints
│   ├── admin/              # Admin-only endpoints
│   ├── auth/               # Authentication (login, signup, support-login)
│   ├── cart/               # Shopping cart operations
│   ├── files/              # File operations (vulnerable to path traversal)
│   ├── flags/              # CTF flag endpoints
│   ├── orders/             # Order management
│   ├── products/           # Product catalog
│   ├── support/            # Support ticket system
│   └── user/               # User profile endpoints
├── components/             # Reusable React components
├── vulnerabilities/        # Vulnerability documentation pages
├── hall-of-fame/           # Hall of Fame page
└── [pages]/                # Next.js pages

content/vulnerabilities/    # Markdown files for each vulnerability
lib/                        # Utilities (api, auth, prisma, types)
prisma/                     # Schema and seed.ts with CTF flags
uploads/                    # User-uploaded files (served via /api/uploads/)
docs/                       # Astro documentation site (separate npm project)
hall-of-fame/data.json      # Hall of Fame entries (community-driven via PRs)
tests/                      # Jest unit and API exploitation tests
├── unit/                   # Unit tests (MD5, JWT, input filters)
├── api/                    # API exploitation scenario tests
├── helpers/api.ts          # Shared test helpers (login, auth, assertions)
└── plans/                  # Per-vulnerability test plan markdown files
cypress/                    # Cypress E2E exploitation workflow tests
├── e2e/                    # E2E spec files
└── support/commands.ts     # Custom commands (login, verifyFlag)
```

## Commands

```bash
# Development
npm run dev                  # Start dev server (port 3000)
npm start                    # Start production server
npm run build                # Build for production

# Code Quality
npm run lint                 # Run ESLint
npm run lint:fix             # Fix ESLint issues
npm run format               # Format with Prettier
npm run format:check         # Check formatting

# Database
npm run db:generate          # Generate Prisma Client
npm run db:push              # Push schema changes
npm run db:migrate           # Run migrations
npm run db:studio            # Open Prisma Studio
npm run db:seed              # Seed database with flags

# Setup
npm run setup                # Full setup (env, deps, seed)

# Docker (no Node.js required)
npm run docker:up            # Build image and start container (detached)
npm run docker:down          # Stop and remove container
npm run docker:build         # Rebuild Docker image
npm run docker:logs          # Follow container logs
npm run docker:reset         # Wipe volumes and restart (full reset)

# Testing
npm run test                 # Run all Jest tests
npm run test:unit            # Unit tests only
npm run test:api             # API exploitation tests (requires running server)
npm run test:e2e             # Cypress E2E tests (requires running server)
npm run test:e2e:open        # Open Cypress interactive mode
npm run test:ci              # All tests (Jest + Cypress)

# Documentation (in docs/)
npm run docs:dev             # Astro dev server
npm run docs:build           # Build Astro site
```

## Coding Standards

- **Language:** All code, comments, documentation in English
- **Comments:** Avoid unless code is not self-explanatory
- **DRY:** Don't Repeat Yourself - avoid code duplication
- **TypeScript:** Strict mode, prefer type inference, use Prisma-generated types from `@/lib/generated/prisma`

### API Routes

- Use Next.js App Router handlers (`route.ts`)
- Export: `GET`, `POST`, `PUT`, `DELETE`
- Auth: `getAuthenticatedUser()` from `@/lib/server-auth`
- DB: `prisma` from `@/lib/prisma`

### Components

- Default to React Server Components
- Add `"use client"` only for interactivity/hooks/browser APIs
- Use Tailwind CSS, ensure responsive design and accessibility

## Security Context

**DO NOT fix intentional vulnerabilities** - they are the core feature.

### Adding New Vulnerabilities

1. Add flag to `prisma/seed.ts` in `OSS{...}` format
2. Add 3 hints in the `flagHints` map in `prisma/seed.ts` (keyed by slug, levels 1→3 from vague to near-solution)
3. Create documentation in `content/vulnerabilities/`
4. Document: overview, vulnerable code, exploitation, mitigation
5. Test exploitability

### CTF Flag System

- Format: `OSS{...}`
- Model: `Flag` with `flag`, `slug`, `category`, `difficulty`, `markdownFile`
- Categories: INJECTION, AUTHENTICATION, AUTHORIZATION, XSS, CSRF, etc.
- Difficulty: EASY, MEDIUM, HARD
- Each flag has 3 progressive hints (stored in `Hint` model, tracked by `RevealedHint`)

## Database Models

| Model              | Purpose                                      |
| ------------------ | -------------------------------------------- |
| User               | Auth (email, password, role: CUSTOMER/ADMIN) |
| Product            | E-commerce catalog                           |
| Cart/CartItem      | Shopping cart                                |
| Order              | Order management with status                 |
| Address            | User and order addresses                     |
| Flag               | CTF flags linked to vulnerabilities          |
| Hint               | Progressive hints per flag (3 levels)        |
| RevealedHint       | Tracks which hints have been revealed        |
| Review             | Product reviews                              |
| SupportAccessToken | Support access tokens                        |

## Environment Variables

```env
DATABASE_URL=           # SQLite connection string
NEXT_PUBLIC_BASE_URL=   # Base URL (default: http://localhost:3000)
```

## Common Patterns

```typescript
// API Authentication
const user = await getAuthenticatedUser(request);
if (!user) {
  return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
}

// Database Query
import { prisma } from "@/lib/prisma";
const products = await prisma.product.findMany();

// Flag Retrieval
const flag = await prisma.flag.findUnique({
  where: { slug: "vulnerability-slug" },
});

// Client Auth Hook
import { useAuth } from "@/hooks/useAuth";
const { user, logout } = useAuth();
```

## Testing

Security regression tests validate that all vulnerability chains and flags remain exploitable. Tests deliberately assert insecure behaviors — they prevent accidental hardening.

- **Jest unit tests** (`tests/unit/`): Test utility functions (MD5 hashing, JWT signing, input filters)
- **Jest API tests** (`tests/api/`): Test exploitation scenarios against API endpoints
- **Cypress E2E tests** (`cypress/e2e/`): Test full exploitation workflows through the UI
- **CI/CD** (`.github/workflows/test.yml`): Runs on PRs to `main` — 3 parallel jobs (unit, API, E2E)

## Notes

- SQLite for simplicity (easy to reset/seed)
- `docs/` is a separate Astro project - run `npm install` there separately
- `docs/` has its own ESLint/Prettier config with Astro plugins
- `create-oss-store` npm package available in `packages/`
- `tests/` and `cypress/` are excluded from `tsconfig.json` and ESLint (they have their own configs)
