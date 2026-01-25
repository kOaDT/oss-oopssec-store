# OSS – OopsSec Store | Project Context for Claude

## Project Overview

OSS – OopsSec Store is an intentionally vulnerable e-commerce web application designed for security training and Capture The Flag (CTF) challenges. It demonstrates real-world security vulnerabilities in a production-like environment built with modern web technologies.

**Critical Note:** This application contains intentional security flaws and must never be deployed in a production environment. All vulnerabilities are documented and serve educational purposes.

## Architecture

### Frontend

- **Framework:** Next.js 16.0.6 (App Router)
- **UI Library:** React 19.2.0
- **Language:** TypeScript 5
- **Styling:** Tailwind CSS 4 with `@tailwindcss/typography`
- **Font:** Poppins (Google Fonts)
- **Markdown Rendering:** `react-markdown` with `remark-gfm` for GitHub Flavored Markdown

### Backend

- **Runtime:** Node.js
- **Framework:** Next.js API Routes (App Router)
- **Database:** SQLite with Prisma ORM 6.19.1
- **Authentication:** JWT tokens (intentionally weak implementation)
- **File Storage:** Local filesystem (`public/uploads/`)

### Development Tools

- **Package Manager:** npm
- **Linting:** ESLint 9 with Next.js config and Prettier
- **Git Hooks:** Husky with lint-staged
- **Type Checking:** TypeScript strict mode
- **Database Tools:** Prisma Studio, Prisma CLI

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
├── hall-of-fame/           # Hall of Fame page for players who found all flags
└── [pages]/                # Next.js pages (cart, checkout, login, support-login, etc.)

content/
└── vulnerabilities/        # Markdown files for each vulnerability

lib/
├── api.ts                  # Client-side API helpers
├── client-auth.ts          # Client-side authentication
├── config.ts               # Configuration utilities
├── database.ts             # Database utilities
├── prisma.ts               # Prisma client instance
├── server-auth.ts          # Server-side authentication (weak JWT)
└── types/                  # TypeScript type definitions

prisma/
├── schema.prisma           # Database schema
└── seed.ts                 # Database seeding with CTF flags

public/
├── exploits/               # Example exploit payloads
└── uploads/                # User-uploaded files

hooks/
└── useAuth.ts              # React hook for authentication

scripts/
└── setup.sh                # Initial setup script

hall-of-fame/
└── data.json               # Hall of Fame entries (community-driven via PRs)

docs/                       # Static documentation site (Astro)
├── src/
│   ├── data/blog/          # Blog posts / walkthroughs (Markdown)
│   └── ...                 # Astro components, layouts, pages
├── public/                 # Static assets
├── astro.config.ts         # Astro configuration
└── package.json            # Separate npm project
```

## Development Commands

```bash
# Development
npm run dev                  # Start Next.js development server (port 3000)

# Prod
npm start                # Start Next.js production server

# Build
npm run build                # Build

# Code Quality
npm run lint                 # Run ESLint
npm run lint:fix             # Fix ESLint issues
npm run format               # Format code with Prettier
npm run format:check         # Check code formatting

# Database
npm run db:generate          # Generate Prisma Client
npm run db:push              # Push schema changes to database
npm run db:migrate           # Run database migrations
npm run db:studio            # Open Prisma Studio
npm run db:seed              # Seed database with initial data and flags

# Setup
npm run setup                # Run setup script (creates .env, installs deps, seeds DB)

# Documentation Site (Astro - in docs/)
npm run docs:dev             # Start Astro development server
npm run docs:build           # Build Astro site
npm run docs:lint            # Run ESLint on docs/
npm run docs:format          # Format docs/ with Prettier
npm run docs:format:check    # Check docs/ formatting
```

## Coding Standards

### General Principles

- **Code Quality:** Write clean, maintainable, professional-quality code
- **Language:** All code, comments, and documentation in English
- **Comments:** Avoid comments unless code is not self-explanatory
- **Security:** This is an intentionally vulnerable application - vulnerabilities are features, not bugs
- **DRY Principle:** Follow "Don't Repeat Yourself" - avoid code duplication
- **Technical Debt:** Avoid introducing unintentional technical debt
- **Research:** Conduct thorough research before implementation
- **Clarification:** Ask questions if requirements are unclear

### TypeScript Guidelines

- Use strict TypeScript configuration
- Prefer type inference where possible
- Use Prisma-generated types from `@/lib/generated/prisma`
- Define shared types in `lib/types/`

### API Route Patterns

- Use Next.js App Router API route handlers (`route.ts`)
- Export named functions: `GET`, `POST`, `PUT`, `DELETE`
- Use `NextRequest` and `NextResponse` from `next/server`
- Authentication via `getAuthenticatedUser()` from `@/lib/server-auth`
- Database access via `prisma` from `@/lib/prisma`
- Return JSON responses with appropriate HTTP status codes

### Component Patterns

- Use React Server Components by default
- Create Client Components (`"use client"`) only when needed (interactivity, hooks, browser APIs)
- Follow Next.js App Router conventions
- Use Tailwind CSS for styling
- Ensure responsive design and accessibility

## Security Context

**IMPORTANT:** This application is intentionally vulnerable. When working on this project:

1. **Intentional Vulnerabilities:** Do not fix intentional security flaws - they are the core feature
2. **New Vulnerabilities:** When adding new vulnerabilities:
   - Add corresponding flag to `prisma/seed.ts` in `OSS{...}` format
   - Create documentation in `content/vulnerabilities/`
   - Ensure the vulnerability is exploitable and educational
3. **Documentation:** All vulnerabilities must be documented with:
   - Overview and why it's dangerous
   - Vulnerable code examples
   - Exploitation techniques
   - Mitigation strategies

## Database Schema

### Key Models

- **User:** Authentication and user data (email, password, role: CUSTOMER/ADMIN)
- **Product:** E-commerce product catalog
- **Cart/CartItem:** Shopping cart functionality
- **Order:** Order management with status tracking
- **Address:** User and order addresses
- **Flag:** CTF flags linked to vulnerabilities (slug, category, difficulty)
- **Review:** Product reviews
- **SupportAccessToken:** Support access tokens for customer support

### Authentication

- Custom React hook `useAuth` in `hooks/useAuth.ts` manages client-side authentication state
- Provides `user` state and `logout` function
- Syncs with localStorage and listens for storage changes across tabs

## UI/UX Guidelines

- **Responsiveness:** Ensure interfaces work on mobile, tablet, and desktop
- **Accessibility:** Follow WCAG guidelines (ARIA labels, keyboard navigation, semantic HTML)
- **Design:** Modern, clean e-commerce aesthetic
- **User Feedback:** Provide clear error messages and loading states
- **Forms:** Include proper validation and user feedback

## CTF Flag System

- Flags are stored in the database (`Flag` model)
- Each flag has:
  - `flag`: The actual flag string in `OSS{...}` format
  - `slug`: Unique identifier matching vulnerability documentation
  - `category`: Vulnerability category (INJECTION, AUTHENTICATION, etc.)
  - `difficulty`: EASY, MEDIUM, or HARD
  - `markdownFile`: Reference to documentation file
- Flags are seeded via `prisma/seed.ts`
- Flags can be retrieved through API endpoints when vulnerabilities are exploited

## Environment Variables

Required environment variables:

- `DATABASE_URL`: SQLite database connection string
- `NEXT_PUBLIC_BASE_URL`: Base URL for the application (defaults to `http://localhost:3000`)

## Workflow

1. **Feature Development:**
   - Implement changes following coding standards
   - Ensure vulnerabilities remain exploitable (if intentional)
   - Update documentation if adding new vulnerabilities

2. **Vulnerability Addition:**
   - Implement vulnerable code
   - Add flag to `prisma/seed.ts`
   - Create markdown documentation in `content/vulnerabilities/`
   - Test exploitability

3. **Code Quality:**
   - Run `npm run lint` and `npm run format:check` at the end of your implementation
   - Ensure TypeScript compiles without errors
   - Test functionality manually

## Documentation References

### Next.js 16 (App Router)

- **Official Docs:** https://nextjs.org/docs
- **App Router:** https://nextjs.org/docs/app
- **API Routes:** https://nextjs.org/docs/app/building-your-application/routing/route-handlers
- **Server Components:** https://nextjs.org/docs/app/building-your-application/rendering/server-components
- **Client Components:** https://nextjs.org/docs/app/building-your-application/rendering/client-components

### Prisma 6

- **Official Docs:** https://www.prisma.io/docs
- **Getting Started:** https://www.prisma.io/docs/getting-started

### Tailwind CSS 4

- **Official Docs:** https://tailwindcss.com/docs
- **Installation:** https://tailwindcss.com/docs/installation
- **Utility Classes:** https://tailwindcss.com/docs/utility-first
- **Responsive Design:** https://tailwindcss.com/docs/responsive-design

## Common Patterns

### API Authentication

```typescript
const user = await getAuthenticatedUser(request);
if (!user) {
  return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
}
```

### Database Queries

```typescript
import { prisma } from "@/lib/prisma";
const products = await prisma.product.findMany();
```

### Flag Retrieval

```typescript
const flag = await prisma.flag.findUnique({
  where: { slug: "vulnerability-slug" },
});
```

## Notes

- The application uses SQLite for simplicity (easy to reset and seed)
- All vulnerabilities are documented with educational content
- There's a `create-oss-store` npm package in `packages/` for quick scaffolding
- Static documentation site available in `docs/` (Astro project with its own `package.json`)
- The `docs/` folder is excluded from the root ESLint/Prettier config (has its own config with Astro plugins)
- Run `npm install` in `docs/` separately before using `docs:*` commands
