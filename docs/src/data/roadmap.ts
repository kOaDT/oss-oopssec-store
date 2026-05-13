export type Difficulty = "EASY" | "MEDIUM" | "HARD";

export interface Challenge {
  title: string;
  difficulty: Difficulty;
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
        difficulty: "EASY",
        walkthroughSlug: "next-public-env-variable-leak",
      },
      {
        title: "Information disclosure via API errors",
        difficulty: "EASY",
        walkthroughSlug: "information-disclosure-api-error",
      },
      {
        title: "Plaintext passwords in logs",
        difficulty: "MEDIUM",
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
        difficulty: "EASY",
        walkthroughSlug: "idor-order-privacy-breach",
      },
      {
        title: "Open redirect to login bypass",
        difficulty: "EASY",
        walkthroughSlug: "open-redirect-login-bypass",
      },
      {
        title: "Broken Object Level Authorization (BOLA)",
        difficulty: "MEDIUM",
        walkthroughSlug: "bola-wishlist-access",
      },
      {
        title: "Path traversal in document API",
        difficulty: "MEDIUM",
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
        difficulty: "MEDIUM",
        walkthroughSlug: "client-side-price-manipulation",
      },
      {
        title: "Mass assignment to admin role",
        difficulty: "MEDIUM",
        walkthroughSlug: "mass-assignment-admin-privilege-escalation",
      },
      {
        title: "Middleware bypass (CVE-2025-29927)",
        difficulty: "MEDIUM",
        walkthroughSlug: "middleware-authorization-bypass-cve-2025-29927",
      },
      {
        title: "Race condition coupon abuse",
        difficulty: "HARD",
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
        difficulty: "EASY",
        walkthroughSlug: "stored-xss-product-reviews",
      },
      {
        title: "Self-XSS in profile bio",
        difficulty: "EASY",
        walkthroughSlug: "self-xss-csrf-profile-takeover",
      },
      {
        title: "CSRF on admin order update",
        difficulty: "MEDIUM",
        walkthroughSlug: "csrf-admin-order-update",
      },
      {
        title: "CSRF + Self-XSS profile takeover",
        difficulty: "HARD",
        walkthroughSlug: "self-xss-csrf-profile-takeover",
        prerequisites: [13, 14],
      },
    ],
  },
  {
    title: "SQL Injection Deep Dive",
    tagline: "One quote, one query, one breach.",
    challenges: [
      {
        title: "SQL injection in order search",
        difficulty: "MEDIUM",
        walkthroughSlug: "sql-injection-writeup",
      },
      {
        title: "Product search SQLi",
        difficulty: "MEDIUM",
        walkthroughSlug: "product-search-sql-injection",
      },
      {
        title: "X-Forwarded-For SQLi",
        difficulty: "HARD",
        walkthroughSlug: "x-forwarded-for-sql-injection",
        prerequisites: [16, 17],
      },
      {
        title: "Second-order SQL injection",
        difficulty: "HARD",
        walkthroughSlug: "second-order-sql-injection",
        prerequisites: [16, 17],
      },
    ],
  },
  {
    title: "Parsers Behaving Badly",
    tagline: "Parsers go where your business logic can't.",
    challenges: [
      {
        title: "Malicious file upload (SVG XSS)",
        difficulty: "HARD",
        walkthroughSlug: "malicious-file-upload-stored-xss",
      },
      {
        title: "XXE in supplier order import",
        difficulty: "HARD",
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
        difficulty: "MEDIUM",
        walkthroughSlug: "jwt-weak-secret-admin-bypass",
      },
      {
        title: "Brute force, no rate limiting",
        difficulty: "MEDIUM",
        walkthroughSlug: "brute-force-no-rate-limiting",
      },
      {
        title: "Session fixation",
        difficulty: "MEDIUM",
        walkthroughSlug: "session-fixation-weak-session-management",
      },
      {
        title: "Insecure password reset",
        difficulty: "MEDIUM",
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
        difficulty: "MEDIUM",
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
        difficulty: "MEDIUM",
        walkthroughSlug: "weak-md5-hashing-admin-compromise",
      },
      {
        title: "Insecure randomness in gift cards",
        difficulty: "MEDIUM",
        walkthroughSlug: "insecure-randomness-gift-card",
      },
      {
        title: "AES-CBC padding oracle",
        difficulty: "HARD",
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
        difficulty: "MEDIUM",
        walkthroughSlug: "prompt-injection-ai-assistant",
      },
      {
        title: "MCP malicious server",
        difficulty: "HARD",
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
        difficulty: "HARD",
        walkthroughSlug: "supply-chain-poisoned-rules-chain",
      },
      {
        title: "AI rules file backdoor",
        difficulty: "MEDIUM",
        walkthroughSlug: "supply-chain-poisoned-rules-chain",
      },
      {
        title: "react2shell (CVE-2025-55182)",
        difficulty: "HARD",
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
