export type Difficulty = "EASY" | "MEDIUM" | "HARD";

/** Vulnerability class. Mirrors the `FlagCategory` enum of
 * `prisma/schema.prisma` verbatim so a consumer can join challenges.json with
 * the app's `/api/flags` on this field. Keep the two in sync: adding a value
 * here without adding it to the enum breaks that join. */
export type Category =
  | "INJECTION"
  | "AUTHENTICATION"
  | "AUTHORIZATION"
  | "REQUEST_FORGERY"
  | "INFORMATION_DISCLOSURE"
  | "INPUT_VALIDATION"
  | "CRYPTOGRAPHIC"
  | "REMOTE_CODE_EXECUTION"
  | "INSECURE_DESIGN"
  | "SUPPLY_CHAIN"
  | "OTHER";

/** Hands-on time to expect, as `[min, max]` minutes. A null max means
 * open-ended ("120+ min"); equal bounds mean a single estimate ("30 min"). */
export type EstimatedMinutes = [number, number | null];

export interface Challenge {
  title: string;
  /** `Flag.slug` in `prisma/flags.ts`. The join key between the curriculum,
   * the app's `/api/flags` and `challenges.json`. Unique across the roadmap. */
  slug: string;
  difficulty: Difficulty;
  category: Category;
  estimatedMinutes: EstimatedMinutes;
  walkthroughSlug: string;
  /** Global challenge numbers (1-indexed across the curriculum) that the
   * learner should ideally have completed first. Rendered as a "Builds on"
   * hint on the challenge card. */
  prerequisites?: number[];
}

export interface Chapter {
  title: string;
  tagline: string;
  challenges: Challenge[];
}

export const CURRICULUM: Chapter[] = [
  {
    title: "Reconnaissance & Disclosure",
    tagline: "Most attacks start with reading, not exploiting.",
    challenges: [
      {
        title: "Public env variable leak",
        slug: "public-env-variable",
        difficulty: "EASY",
        category: "INFORMATION_DISCLOSURE",
        estimatedMinutes: [15, 20],
        walkthroughSlug: "next-public-env-variable-leak",
      },
      {
        title: "Information disclosure via API errors",
        slug: "information-disclosure-api-error",
        difficulty: "EASY",
        category: "INFORMATION_DISCLOSURE",
        estimatedMinutes: [15, 20],
        walkthroughSlug: "information-disclosure-api-error",
      },
      {
        title: "Plaintext passwords in logs",
        slug: "plaintext-password-in-logs",
        difficulty: "MEDIUM",
        category: "INFORMATION_DISCLOSURE",
        estimatedMinutes: [30, 30],
        walkthroughSlug: "plaintext-password-in-logs",
      },
    ],
  },
  {
    title: "Broken Access Control",
    tagline: "The bug almost every API has somewhere.",
    challenges: [
      {
        title: "Insecure Direct Object Reference (IDOR)",
        slug: "insecure-direct-object-reference",
        difficulty: "EASY",
        category: "AUTHORIZATION",
        estimatedMinutes: [20, 30],
        walkthroughSlug: "idor-order-privacy-breach",
      },
      {
        title: "Open redirect to login bypass",
        slug: "open-redirect",
        difficulty: "EASY",
        category: "INPUT_VALIDATION",
        estimatedMinutes: [20, 30],
        walkthroughSlug: "open-redirect-login-bypass",
      },
      {
        title: "Broken Object Level Authorization (BOLA)",
        slug: "broken-object-level-authorization",
        difficulty: "MEDIUM",
        category: "AUTHORIZATION",
        estimatedMinutes: [45, 60],
        walkthroughSlug: "bola-wishlist-access",
      },
      {
        title: "Broken Function Level Authorization (live stream hijack)",
        slug: "broken-function-level-authorization",
        difficulty: "MEDIUM",
        category: "AUTHORIZATION",
        estimatedMinutes: [45, 60],
        walkthroughSlug: "live-stream-hijack",
      },
      {
        title: "Path traversal in document API",
        slug: "path-traversal",
        difficulty: "MEDIUM",
        category: "INPUT_VALIDATION",
        estimatedMinutes: [30, 45],
        walkthroughSlug: "path-traversal-documents-api",
      },
    ],
  },
  {
    title: "Trusting the Client",
    tagline: "Whatever the browser sends, the server has to verify.",
    challenges: [
      {
        title: "Client-side price manipulation",
        slug: "client-side-price-manipulation",
        difficulty: "MEDIUM",
        category: "INPUT_VALIDATION",
        estimatedMinutes: [30, 45],
        walkthroughSlug: "client-side-price-manipulation",
      },
      {
        title: "Mass assignment to admin role",
        slug: "mass-assignment",
        difficulty: "MEDIUM",
        category: "INPUT_VALIDATION",
        estimatedMinutes: [45, 60],
        walkthroughSlug: "mass-assignment-admin-privilege-escalation",
      },
      {
        title: "Middleware bypass (CVE-2025-29927)",
        slug: "middleware-authorization-bypass",
        difficulty: "MEDIUM",
        category: "AUTHORIZATION",
        estimatedMinutes: [30, 45],
        walkthroughSlug: "middleware-authorization-bypass-cve-2025-29927",
      },
      {
        title: "Race condition coupon abuse",
        slug: "race-condition-coupon-abuse",
        difficulty: "HARD",
        category: "INSECURE_DESIGN",
        estimatedMinutes: [45, 90],
        walkthroughSlug: "race-condition-coupon-abuse",
      },
    ],
  },
  {
    title: "Cross-Site Attacks",
    tagline: "Your input, running in someone else's browser.",
    challenges: [
      {
        title: "Stored XSS in product reviews",
        slug: "cross-site-scripting-xss",
        difficulty: "EASY",
        category: "INJECTION",
        estimatedMinutes: [30, 45],
        walkthroughSlug: "stored-xss-product-reviews",
      },
      {
        title: "Self-XSS in profile bio",
        slug: "self-xss-profile-injection",
        difficulty: "EASY",
        category: "INJECTION",
        estimatedMinutes: [20, 30],
        walkthroughSlug: "self-xss-csrf-profile-takeover",
      },
      {
        title: "CSRF on admin order update",
        slug: "cross-site-request-forgery",
        difficulty: "MEDIUM",
        category: "REQUEST_FORGERY",
        estimatedMinutes: [45, 60],
        walkthroughSlug: "csrf-admin-order-update",
      },
      {
        title: "CSRF + Self-XSS profile takeover",
        slug: "csrf-profile-takeover-chain",
        difficulty: "HARD",
        category: "REQUEST_FORGERY",
        estimatedMinutes: [90, 120],
        walkthroughSlug: "self-xss-csrf-profile-takeover",
        prerequisites: [14, 15],
      },
    ],
  },
  {
    title: "SQL Injection Deep Dive",
    tagline: "One quote, one query, one breach.",
    challenges: [
      {
        title: "SQL injection in order search",
        slug: "sql-injection",
        difficulty: "MEDIUM",
        category: "INJECTION",
        estimatedMinutes: [30, 45],
        walkthroughSlug: "sql-injection-writeup",
      },
      {
        title: "Product search SQLi",
        slug: "product-search-sql-injection",
        difficulty: "MEDIUM",
        category: "INJECTION",
        estimatedMinutes: [30, 45],
        walkthroughSlug: "product-search-sql-injection",
      },
      {
        title: "X-Forwarded-For SQLi",
        slug: "x-forwarded-for-sql-injection",
        difficulty: "HARD",
        category: "INJECTION",
        estimatedMinutes: [60, 90],
        walkthroughSlug: "x-forwarded-for-sql-injection",
        prerequisites: [17, 18],
      },
      {
        title: "Second-order SQL injection",
        slug: "second-order-sql-injection",
        difficulty: "HARD",
        category: "INJECTION",
        estimatedMinutes: [60, 90],
        walkthroughSlug: "second-order-sql-injection",
        prerequisites: [17, 18],
      },
    ],
  },
  {
    title: "Parsers Behaving Badly",
    tagline: "Parsers go where your business logic can't.",
    challenges: [
      {
        title: "Malicious file upload (SVG XSS)",
        slug: "malicious-file-upload",
        difficulty: "HARD",
        category: "INJECTION",
        estimatedMinutes: [45, 60],
        walkthroughSlug: "malicious-file-upload-stored-xss",
      },
      {
        title: "XXE in supplier order import",
        slug: "xxe-supplier-order-import",
        difficulty: "HARD",
        category: "INJECTION",
        estimatedMinutes: [45, 60],
        walkthroughSlug: "xxe-supplier-order-import",
      },
    ],
  },
  {
    title: "Authentication Failures",
    tagline: "Login is a feature. Auth is a system.",
    challenges: [
      {
        title: "Weak JWT secret",
        slug: "weak-jwt-secret",
        difficulty: "MEDIUM",
        category: "AUTHENTICATION",
        estimatedMinutes: [45, 60],
        walkthroughSlug: "jwt-weak-secret-admin-bypass",
      },
      {
        title: "Brute force, no rate limiting",
        slug: "brute-force-no-rate-limiting",
        difficulty: "MEDIUM",
        category: "AUTHENTICATION",
        estimatedMinutes: [30, 45],
        walkthroughSlug: "brute-force-no-rate-limiting",
      },
      {
        title: "Session fixation",
        slug: "session-fixation-weak-session-management",
        difficulty: "MEDIUM",
        category: "AUTHENTICATION",
        estimatedMinutes: [60, 90],
        walkthroughSlug: "session-fixation-weak-session-management",
      },
      {
        title: "Insecure password reset",
        slug: "insecure-password-reset",
        difficulty: "MEDIUM",
        category: "AUTHENTICATION",
        estimatedMinutes: [45, 60],
        walkthroughSlug: "insecure-password-reset",
      },
    ],
  },
  {
    title: "Server-Side Request Forgery",
    tagline: "Make the server fetch what you can't.",
    challenges: [
      {
        title: "SSRF internal page access",
        slug: "server-side-request-forgery",
        difficulty: "MEDIUM",
        category: "REQUEST_FORGERY",
        estimatedMinutes: [45, 60],
        walkthroughSlug: "ssrf-internal-page-access",
      },
    ],
  },
  {
    title: "Cryptography Done Wrong",
    tagline: "Modern crypto is safe by default. Until it isn't.",
    challenges: [
      {
        title: "Weak MD5 password hashing",
        slug: "weak-md5-hashing",
        difficulty: "MEDIUM",
        category: "CRYPTOGRAPHIC",
        estimatedMinutes: [30, 45],
        walkthroughSlug: "weak-md5-hashing-admin-compromise",
      },
      {
        title: "Insecure randomness in gift cards",
        slug: "insecure-randomness-gift-card",
        difficulty: "MEDIUM",
        category: "CRYPTOGRAPHIC",
        estimatedMinutes: [45, 60],
        walkthroughSlug: "insecure-randomness-gift-card",
      },
      {
        title: "AES-CBC padding oracle",
        slug: "aes-cbc-padding-oracle",
        difficulty: "HARD",
        category: "CRYPTOGRAPHIC",
        estimatedMinutes: [90, 120],
        walkthroughSlug: "aes-cbc-padding-oracle-forged-share-token",
      },
    ],
  },
  {
    title: "AI & LLM Security",
    tagline: "The new attack surface nobody trained for.",
    challenges: [
      {
        title: "Prompt injection in AI assistant",
        slug: "prompt-injection-ai-assistant",
        difficulty: "MEDIUM",
        category: "INJECTION",
        estimatedMinutes: [60, 90],
        walkthroughSlug: "prompt-injection-ai-assistant",
      },
      {
        title: "MCP malicious server",
        slug: "mcp-malicious-server",
        difficulty: "HARD",
        category: "INJECTION",
        estimatedMinutes: [90, 120],
        walkthroughSlug: "mcp-malicious-server",
      },
    ],
  },
  {
    title: "Supply Chain & Framework",
    tagline: "Your code is fine. The 800 packages around it aren't.",
    challenges: [
      {
        title: "npm typosquat",
        slug: "npm-supply-chain-typosquat",
        difficulty: "HARD",
        category: "SUPPLY_CHAIN",
        estimatedMinutes: [60, 90],
        walkthroughSlug: "supply-chain-poisoned-rules-chain",
      },
      {
        title: "AI rules file backdoor",
        slug: "ai-rules-file-backdoor",
        difficulty: "MEDIUM",
        category: "SUPPLY_CHAIN",
        estimatedMinutes: [20, 30],
        walkthroughSlug: "supply-chain-poisoned-rules-chain",
      },
      {
        title: "react2shell (CVE-2025-55182)",
        slug: "react2shell",
        difficulty: "HARD",
        category: "REMOTE_CODE_EXECUTION",
        estimatedMinutes: [120, null],
        walkthroughSlug: "react2shell-cve-2025-55182",
      },
    ],
  },
];

export const TOTAL_CHALLENGES = CURRICULUM.reduce(
  (sum, chapter) => sum + chapter.challenges.length,
  0
);

export const CHALLENGES_BY_DIFFICULTY = CURRICULUM.flatMap(
  c => c.challenges
).reduce<Record<Difficulty, number>>(
  (acc, ch) => {
    acc[ch.difficulty] += 1;
    return acc;
  },
  { EASY: 0, MEDIUM: 0, HARD: 0 }
);
