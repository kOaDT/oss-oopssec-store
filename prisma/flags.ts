import type { FlagCategory, FlagDifficulty } from "../lib/types";

/**
 * Single source of truth for the CTF curriculum.
 *
 * `tests/unit/challenge-parity.test.ts` cross-checks every entry here against
 * `content/vulnerabilities/`, `tests/helpers/flags.ts`, `docs/src/data/roadmap.ts`,
 * `docs/src/data/blog/` and the challenge counts in README.md / EDUCATORS.md.
 * Run `npm run test:unit` after editing this file: it tells you exactly which
 * of those places you still have to update.
 *
 * Adding a challenge (see CONTRIBUTING.md for the full checklist):
 *
 * 1. Append an entry to `flags` below.
 *    - `flag` follows the `OSS{...}` format and must be unique.
 *    - `slug` is the URL segment of `/vulnerabilities/<slug>`, kebab-case.
 *    - `markdownFile` names a file in `content/vulnerabilities/`.
 *    - `walkthroughSlug` is the id of a post in `docs/src/data/blog/` (its
 *      frontmatter `slug` if it has one, otherwise the file name without
 *      `.md`). Required: every challenge sits on the roadmap, and the roadmap
 *      links to a walkthrough. An unfinished post can ship as `draft: true`.
 *      Two chained challenges may share one post.
 *    - `cve` (e.g. "CVE-2025-29927"), `cwe` (e.g. "CWE-89") and `owasp` are
 *      optional and surfaced as badges in the UI. `owasp` takes an OWASP Top 10
 *      2025 id (e.g. "A05:2025"); legacy 2021 ids like "A10:2021" are accepted
 *      for categories that no longer exist in 2025, such as SSRF.
 * 2. Add exactly three hints to `flagHints`, keyed by the same slug, ordered
 *    from vague nudge (level 1) to near-solution (level 3).
 *
 * Categories map 1:1 onto the `FlagCategory` enum in `prisma/schema.prisma`:
 * INJECTION, AUTHENTICATION, AUTHORIZATION, REQUEST_FORGERY,
 * INFORMATION_DISCLOSURE, INPUT_VALIDATION, CRYPTOGRAPHIC,
 * REMOTE_CODE_EXECUTION, INSECURE_DESIGN, SUPPLY_CHAIN, OTHER.
 *
 * Difficulty levels:
 * - EASY: basic exploitation, no special tooling
 * - MEDIUM: requires understanding the vulnerability class
 * - HARD: multi-step exploitation or deep knowledge
 */
export interface ChallengeFlag {
  flag: string;
  slug: string;
  cve?: string;
  cwe?: string;
  owasp?: string;
  markdownFile: string;
  /** Nullable on the `Flag` model, but mandatory here: the parity suite
   * requires every flag to appear on the roadmap, which always links out. */
  walkthroughSlug: string;
  category: FlagCategory;
  difficulty: FlagDifficulty;
}

export const flags: ChallengeFlag[] = [
  {
    flag: "OSS{r3act2sh3ll}",
    slug: "react2shell",
    cve: "CVE-2025-55182",
    cwe: "CWE-502",
    owasp: "A08:2025",
    markdownFile: "react2shell.md",
    walkthroughSlug: "react2shell-cve-2025-55182",
    category: "REMOTE_CODE_EXECUTION",
    difficulty: "HARD",
  },
  {
    flag: "OSS{public_3nvir0nment_v4ri4bl3}",
    slug: "public-env-variable",
    cwe: "CWE-200",
    owasp: "A02:2025",
    markdownFile: "public-env-variable.md",
    walkthroughSlug: "next-public-env-variable-leak",
    category: "INFORMATION_DISCLOSURE",
    difficulty: "EASY",
  },
  {
    flag: "OSS{w34k_jwt_s3cr3t_k3y}",
    slug: "weak-jwt-secret",
    cwe: "CWE-347",
    owasp: "A04:2025",
    markdownFile: "weak-jwt-secret.md",
    walkthroughSlug: "jwt-weak-secret-admin-bypass",
    category: "AUTHENTICATION",
    difficulty: "MEDIUM",
  },
  {
    flag: "OSS{cl13nt_s1d3_pr1c3_m4n1pul4t10n}",
    slug: "client-side-price-manipulation",
    cwe: "CWE-602",
    owasp: "A06:2025",
    markdownFile: "client-side-price-manipulation.md",
    walkthroughSlug: "client-side-price-manipulation",
    category: "INPUT_VALIDATION",
    difficulty: "MEDIUM",
  },
  {
    flag: "OSS{w34k_md5_h4sh1ng}",
    slug: "weak-md5-hashing",
    cwe: "CWE-328",
    owasp: "A04:2025",
    markdownFile: "weak-md5-hashing.md",
    walkthroughSlug: "weak-md5-hashing-admin-compromise",
    category: "CRYPTOGRAPHIC",
    difficulty: "MEDIUM",
  },
  {
    flag: "OSS{1ns3cur3_d1r3ct_0bj3ct_r3f3r3nc3}",
    slug: "insecure-direct-object-reference",
    cwe: "CWE-639",
    owasp: "A01:2025",
    markdownFile: "insecure-direct-object-reference.md",
    walkthroughSlug: "idor-order-privacy-breach",
    category: "AUTHORIZATION",
    difficulty: "EASY",
  },
  {
    flag: "OSS{cr0ss_s1t3_scr1pt1ng_xss}",
    slug: "cross-site-scripting-xss",
    cwe: "CWE-79",
    owasp: "A05:2025",
    markdownFile: "cross-site-scripting-xss.md",
    walkthroughSlug: "stored-xss-product-reviews",
    category: "INJECTION",
    difficulty: "EASY",
  },
  {
    flag: "OSS{cr0ss_s1t3_r3qu3st_f0rg3ry}",
    slug: "cross-site-request-forgery",
    cwe: "CWE-352",
    owasp: "A01:2025",
    markdownFile: "cross-site-request-forgery.md",
    walkthroughSlug: "csrf-admin-order-update",
    category: "REQUEST_FORGERY",
    difficulty: "MEDIUM",
  },
  {
    flag: "OSS{m4ss_4ss1gnm3nt_vuln3r4b1l1ty}",
    slug: "mass-assignment",
    cwe: "CWE-915",
    owasp: "A08:2025",
    markdownFile: "mass-assignment.md",
    walkthroughSlug: "mass-assignment-admin-privilege-escalation",
    category: "INPUT_VALIDATION",
    difficulty: "MEDIUM",
  },
  {
    flag: "OSS{p4th_tr4v3rs4l_4tt4ck}",
    slug: "path-traversal",
    cwe: "CWE-22",
    owasp: "A01:2025",
    markdownFile: "path-traversal.md",
    walkthroughSlug: "path-traversal-documents-api",
    category: "INPUT_VALIDATION",
    difficulty: "MEDIUM",
  },
  {
    flag: "OSS{s3rv3r_s1d3_r3qu3st_f0rg3ry}",
    slug: "server-side-request-forgery",
    cwe: "CWE-918",
    owasp: "A10:2021",
    markdownFile: "server-side-request-forgery.md",
    walkthroughSlug: "ssrf-internal-page-access",
    category: "REQUEST_FORGERY",
    difficulty: "MEDIUM",
  },
  {
    flag: "OSS{sql_1nj3ct10n_vuln3r4b1l1ty}",
    slug: "sql-injection",
    cwe: "CWE-89",
    owasp: "A05:2025",
    markdownFile: "sql-injection.md",
    walkthroughSlug: "sql-injection-writeup",
    category: "INJECTION",
    difficulty: "MEDIUM",
  },
  {
    flag: "OSS{1nf0_d1scl0sur3_4p1_3rr0r}",
    slug: "information-disclosure-api-error",
    cwe: "CWE-209",
    owasp: "A02:2025",
    markdownFile: "information-disclosure-api-error.md",
    walkthroughSlug: "information-disclosure-api-error",
    category: "INFORMATION_DISCLOSURE",
    difficulty: "EASY",
  },
  {
    flag: "OSS{m4l1c10us_f1l3_upl04d_xss}",
    slug: "malicious-file-upload",
    cwe: "CWE-434",
    owasp: "A06:2025",
    walkthroughSlug: "malicious-file-upload-stored-xss",
    markdownFile: "malicious-file-upload.md",
    category: "INJECTION",
    difficulty: "HARD",
  },
  {
    flag: "OSS{pr0duct_s34rch_sql_1nj3ct10n}",
    slug: "product-search-sql-injection",
    cwe: "CWE-89",
    owasp: "A05:2025",
    walkthroughSlug: "product-search-sql-injection",
    markdownFile: "product-search-sql-injection.md",
    category: "INJECTION",
    difficulty: "MEDIUM",
  },
  {
    flag: "OSS{s3ss10n_f1x4t10n_4tt4ck}",
    slug: "session-fixation-weak-session-management",
    cwe: "CWE-384",
    owasp: "A07:2025",
    markdownFile: "session-fixation-weak-session-management.md",
    walkthroughSlug: "session-fixation-weak-session-management",
    category: "AUTHENTICATION",
    difficulty: "MEDIUM",
  },
  {
    flag: "OSS{brut3_f0rc3_n0_r4t3_l1m1t}",
    slug: "brute-force-no-rate-limiting",
    cwe: "CWE-307",
    owasp: "A07:2025",
    markdownFile: "brute-force-no-rate-limiting.md",
    walkthroughSlug: "brute-force-no-rate-limiting",
    category: "AUTHENTICATION",
    difficulty: "MEDIUM",
  },
  {
    flag: "OSS{x_f0rw4rd3d_f0r_sql1}",
    slug: "x-forwarded-for-sql-injection",
    cwe: "CWE-89",
    owasp: "A05:2025",
    markdownFile: "x-forwarded-for-sql-injection.md",
    walkthroughSlug: "x-forwarded-for-sql-injection",
    category: "INJECTION",
    difficulty: "HARD",
  },
  {
    flag: "OSS{pr0mpt_1nj3ct10n_41_4ss1st4nt}",
    slug: "prompt-injection-ai-assistant",
    cwe: "CWE-77",
    owasp: "A05:2025",
    markdownFile: "prompt-injection-ai-assistant.md",
    walkthroughSlug: "prompt-injection-ai-assistant",
    category: "INJECTION",
    difficulty: "MEDIUM",
  },
  {
    flag: "OSS{brok3n_0bj3ct_l3v3l_4uth0r1z4t10n}",
    slug: "broken-object-level-authorization",
    cwe: "CWE-639",
    owasp: "A01:2025",
    walkthroughSlug: "bola-wishlist-access",
    markdownFile: "broken-object-level-authorization.md",
    category: "AUTHORIZATION",
    difficulty: "MEDIUM",
  },
  {
    flag: "OSS{brok3n_funct10n_l3v3l_4uth0r1z4t10n}",
    slug: "broken-function-level-authorization",
    cwe: "CWE-862",
    owasp: "A01:2025",
    walkthroughSlug: "live-stream-hijack",
    markdownFile: "broken-function-level-authorization.md",
    category: "AUTHORIZATION",
    difficulty: "MEDIUM",
  },
  {
    flag: "OSS{s3c0nd_0rd3r_sql_1nj3ct10n}",
    slug: "second-order-sql-injection",
    cwe: "CWE-89",
    owasp: "A05:2025",
    markdownFile: "second-order-sql-injection.md",
    walkthroughSlug: "second-order-sql-injection",
    category: "INJECTION",
    difficulty: "HARD",
  },
  {
    flag: "OSS{pl41nt3xt_p4ssw0rd_1n_l0gs}",
    slug: "plaintext-password-in-logs",
    cwe: "CWE-532",
    owasp: "A09:2025",
    markdownFile: "plaintext-password-in-logs.md",
    walkthroughSlug: "plaintext-password-in-logs",
    category: "INFORMATION_DISCLOSURE",
    difficulty: "MEDIUM",
  },
  {
    flag: "OSS{xml_3xt3rn4l_3nt1ty_1nj3ct10n}",
    slug: "xxe-supplier-order-import",
    cwe: "CWE-611",
    owasp: "A02:2025",
    markdownFile: "xxe-supplier-order-import.md",
    walkthroughSlug: "xxe-supplier-order-import",
    category: "INJECTION",
    difficulty: "HARD",
  },
  {
    flag: "OSS{1ns3cur3_p4ssw0rd_r3s3t}",
    slug: "insecure-password-reset",
    cwe: "CWE-640",
    owasp: "A07:2025",
    markdownFile: "insecure-password-reset.md",
    walkthroughSlug: "insecure-password-reset",
    category: "AUTHENTICATION",
    difficulty: "MEDIUM",
  },
  {
    flag: "OSS{0p3n_r3d1r3ct_l0g1n_byp4ss}",
    slug: "open-redirect",
    cwe: "CWE-601",
    owasp: "A01:2025",
    markdownFile: "open-redirect.md",
    walkthroughSlug: "open-redirect-login-bypass",
    category: "INPUT_VALIDATION",
    difficulty: "EASY",
  },
  {
    flag: "OSS{s3lf_xss_pr0f1l3_1nj3ct10n}",
    slug: "self-xss-profile-injection",
    cwe: "CWE-79",
    owasp: "A05:2025",
    markdownFile: "self-xss-profile-injection.md",
    walkthroughSlug: "self-xss-csrf-profile-takeover",
    category: "INJECTION",
    difficulty: "EASY",
  },
  {
    flag: "OSS{csrf_pr0f1l3_t4k30v3r_ch41n}",
    slug: "csrf-profile-takeover-chain",
    cwe: "CWE-352",
    owasp: "A01:2025",
    markdownFile: "csrf-profile-takeover-chain.md",
    walkthroughSlug: "self-xss-csrf-profile-takeover",
    category: "REQUEST_FORGERY",
    difficulty: "HARD",
  },
  {
    flag: "OSS{p4dd1ng_0r4cl3_f0rg3d_t0k3n}",
    slug: "aes-cbc-padding-oracle",
    cwe: "CWE-327",
    owasp: "A04:2025",
    markdownFile: "aes-cbc-padding-oracle.md",
    walkthroughSlug: "aes-cbc-padding-oracle-forged-share-token",
    category: "CRYPTOGRAPHIC",
    difficulty: "HARD",
  },
  {
    flag: "OSS{mcp_p01s0n3d_t00l_r3sp0ns3}",
    slug: "mcp-malicious-server",
    cwe: "CWE-77",
    owasp: "A05:2025",
    markdownFile: "mcp-malicious-server.md",
    walkthroughSlug: "mcp-malicious-server",
    category: "INJECTION",
    difficulty: "HARD",
  },
  {
    flag: "OSS{m1ddl3w4r3_byp4ss}",
    slug: "middleware-authorization-bypass",
    cve: "CVE-2025-29927",
    cwe: "CWE-285",
    owasp: "A01:2025",
    markdownFile: "middleware-authorization-bypass.md",
    walkthroughSlug: "middleware-authorization-bypass-cve-2025-29927",
    category: "AUTHORIZATION",
    difficulty: "MEDIUM",
  },
  {
    flag: "OSS{r4c3_c0nd1t10n_c0up0n_4bus3}",
    slug: "race-condition-coupon-abuse",
    cwe: "CWE-362",
    owasp: "A06:2025",
    markdownFile: "race-condition-coupon.md",
    walkthroughSlug: "race-condition-coupon-abuse",
    category: "INSECURE_DESIGN",
    difficulty: "HARD",
  },
  {
    flag: "OSS{1ns3cur3_r4nd0mn3ss_g1ft_c4rd}",
    slug: "insecure-randomness-gift-card",
    cwe: "CWE-338",
    owasp: "A04:2025",
    markdownFile: "insecure-randomness-gift-card.md",
    walkthroughSlug: "insecure-randomness-gift-card",
    category: "CRYPTOGRAPHIC",
    difficulty: "MEDIUM",
  },
  {
    flag: "OSS{npm_typ0sqv4tt1ng_dr0p_4i_rul3s}",
    slug: "npm-supply-chain-typosquat",
    cwe: "CWE-829",
    owasp: "A03:2025",
    markdownFile: "npm-supply-chain-typosquat.md",
    walkthroughSlug: "supply-chain-poisoned-rules-chain",
    category: "SUPPLY_CHAIN",
    difficulty: "HARD",
  },
  {
    flag: "OSS{rul3s_f1l3_b4ckd00r_3xpl01t3d}",
    slug: "ai-rules-file-backdoor",
    cwe: "CWE-798",
    owasp: "A07:2025",
    markdownFile: "ai-rules-file-backdoor.md",
    walkthroughSlug: "supply-chain-poisoned-rules-chain",
    category: "SUPPLY_CHAIN",
    difficulty: "MEDIUM",
  },
  {
    flag: "OSS{jwt_4lg_c0nfus10n}",
    slug: "jwt-algorithm-confusion",
    cwe: "CWE-347",
    owasp: "A04:2025",
    markdownFile: "jwt-algorithm-confusion.md",
    walkthroughSlug: "jwt-algorithm-confusion-partner-api",
    category: "CRYPTOGRAPHIC",
    difficulty: "HARD",
  },
];

export const flagHints: Record<string, string[]> = {
  "public-env-variable": [
    "Some secrets hide in plain sight, right in your browser's reach.",
    "Next.js exposes environment variables to the client if they follow a specific naming convention. Check the page source for leaked config values.",
    "Variables prefixed with NEXT_PUBLIC_ are bundled into client-side JavaScript. Search the page source or JS bundles for a base64-encoded string, decode it to reveal the flag.",
  ],
  "weak-md5-hashing": [
    "Once you have access to user data, not all hashing algorithms are created equal.",
    "If you've extracted password hashes from the database, notice they're 32 hex characters, a format associated with a cryptographically broken algorithm from the 1990s.",
    "The hashes are MD5. Use a SQL injection to dump the users table and grab the admin's password hash. Then crack it using an online rainbow table like crackstation.net. Log in as admin to claim the flag.",
  ],
  "insecure-direct-object-reference": [
    "What happens when you peek at someone else's receipt?",
    "Order IDs follow a sequential and predictable pattern. The API doesn't verify whether the order actually belongs to the requesting user.",
    "Access the /api/orders/ endpoint with a different order ID like ORD-001 or ORD-002. The server returns the order data even if it doesn't belong to you, along with a bonus in the response.",
  ],
  "cross-site-scripting-xss": [
    "Your words carry more power here than you think.",
    "Product reviews are rendered directly into the page without sanitization. Any HTML or JavaScript you submit will execute in other users' browsers.",
    "Submit a product review containing a script tag that fetches /xss-flag.txt and displays its content. Something like <script>fetch('/xss-flag.txt').then(r=>r.text()).then(alert)</script> will do the trick.",
  ],
  "information-disclosure-api-error": [
    "Errors can be surprisingly chatty when you provoke them.",
    "Try sending unexpected or malformed data to API endpoints. Some error responses include verbose debug information that goes far beyond a simple error message.",
    "The Data Export UI only offers checkboxes with valid fields, but the API doesn't enforce that. Send a POST request to /api/user/export with an invalid field name in the fields array. The error response includes system diagnostics containing feature flags.",
  ],
  "weak-jwt-secret": [
    "The token on your lips has a secret, and it's an open one.",
    "Decode your authentication token using a tool like jwt.io. The payload itself contains a hint about the signing key's strength.",
    "Your JWT payload includes a hint field saying 'The secret is not so secret'. The signing key is literally the word 'secret'. Forge a new token with role set to ADMIN using HS256, then access /api/admin.",
  ],
  "client-side-price-manipulation": [
    "The cashier trusts whatever number you hand them.",
    "During checkout, the total price is sent from the frontend to the server. The server accepts this value without recalculating it from the cart contents.",
    "Intercept the POST request to /api/orders during checkout using your browser's DevTools or a proxy. Change the 'total' field in the request body to a lower value like 0.01 and observe the response.",
  ],
  "cross-site-request-forgery": [
    "Sometimes the most dangerous links are the ones you can't see.",
    "The admin dashboard hints at hidden content. Inspect the page source for links styled with display:none, one leads to a proof-of-concept demonstration.",
    "View the source of the admin page and find the hidden link to /exploits/csrf-attack.html. Visit it while logged in as admin. The page uses your authentication cookie to submit a forged request that changes an order status, and the flag is returned in the response.",
  ],
  "mass-assignment": [
    "The signup form shows you some fields. The API accepts more.",
    "When creating an account, the backend blindly accepts extra fields beyond email and password. One of those fields controls user permissions.",
    "Add a 'role' field set to 'ADMIN' in the POST /api/auth/signup request body alongside your email and password. The server assigns it without validation. Then visit /api/admin to claim your flag.",
  ],
  "path-traversal": [
    "Sometimes you can walk where you're not supposed to go.",
    "A file-serving API endpoint builds file paths from user input without sanitizing directory traversal sequences. You can escape the intended directory.",
    "The /api/files endpoint serves files from a documents/ directory. Use the 'file' query parameter with ../ sequences to escape, for example, /api/files?file=../flag.txt reads a flag file at the project root.",
  ],
  "server-side-request-forgery": [
    "The server is happy to make requests on your behalf anywhere.",
    "A support feature fetches resources from URLs you provide. It doesn't restrict those URLs to external hosts, so internal services are reachable too.",
    "Submit a support request with the screenshotUrl field pointing to an internal endpoint like http://localhost:3000/internal. The server fetches it with an internal request header and returns the response content to you.",
  ],
  "sql-injection": [
    "The search speaks SQL if you ask it nicely.",
    "The order search endpoint constructs SQL queries by concatenating user input directly. The status filter is not parameterized.",
    "Send a POST to /api/orders/search with a crafted 'status' field containing SQL syntax. A UNION-based injection like ' UNION SELECT ... FROM users -- can extract data from other tables. Watch out for server-side keyword filters.",
  ],
  "product-search-sql-injection": [
    "The search bar understands more languages than you'd expect.",
    "Product search queries are built using string concatenation with the user's search term. The input lands directly inside a SQL LIKE clause.",
    "Search for a term containing SQL syntax, even a simple ' UNION SELECT-- in the q parameter at /api/products/search will be detected as injection. The server rewards the attempt by including the flag in its response.",
  ],
  "session-fixation-weak-session-management": [
    "Support access might be a bit too... generous.",
    "The support access token system lets you generate login tokens. Look closely at whose token you can create, the API might not restrict the target user.",
    "The /api/user/support-access endpoint accepts an optional 'email' parameter. Generate a support token for an admin account, then use /api/auth/support-login?token=... to log in as them and access /api/admin.",
  ],
  "brute-force-no-rate-limiting": [
    "Persistence pays off when nobody's counting your attempts.",
    "The login endpoint doesn't enforce any limit on failed attempts. There is no lockout, no delay, and no CAPTCHA. A specific user has a weak, common password.",
    "Target the account vis.bruta@example.com at POST /api/auth/login. There's no rate limiting, so try common passwords from a wordlist. The password is among the most popular ones. The flag appears in the login response on success.",
  ],
  "malicious-file-upload": [
    "Not all images are as innocent as they look.",
    "The file upload feature allows SVG files, which can contain embedded JavaScript. The server doesn't strip active content from uploaded files.",
    "Upload an SVG file containing a <script> tag or an event handler (like onload) to a product image endpoint at /api/admin/products/[id]/image. The server detects the malicious content and reveals the flag in the response.",
  ],
  react2shell: [
    "Even your framework can betray you. Check the dependency tree.",
    "The project uses a React version affected by a critical CVE that allows remote code execution through the server-side rendering pipeline.",
    "CVE-2025-55182 affects React 19.x's Flight protocol used in Server Components. The vulnerability exploits unsafe deserialization to achieve prototype pollution and then RCE. Look up the public PoC and send a crafted payload to the server's root endpoint.",
  ],
  "x-forwarded-for-sql-injection": [
    "Logs eat whatever headers you feed them.",
    "The visitor tracking system records HTTP headers in a database. Not all headers go through sanitization before being inserted into SQL queries.",
    "Send a POST request to /api/tracking and include SQL syntax in the X-Forwarded-For header. The server inserts this header value directly into an INSERT query on the visitor_logs table. Any SQL keyword in the header triggers injection detection and reveals the flag.",
  ],
  "prompt-injection-ai-assistant": [
    "The AI assistant knows more than it's supposed to share.",
    "The site's chatbot runs on a system prompt that contains sensitive internal configuration. With the right input, you can make it reveal what it was told to keep hidden.",
    "The AI assistant at /api/ai-assistant has a system prompt containing an internal validation code between marker lines. Ask it to repeat its instructions, reveal its internal configuration, or output everything between the --- delimiters. Some filter bypass may be needed.",
  ],
  "broken-object-level-authorization": [
    "Wishlists are personal, unless the API disagrees.",
    "The wishlist API retrieves any wishlist by its ID without verifying that the requesting user is the owner. Some wishlist IDs follow a predictable internal naming convention.",
    "Access GET /api/wishlists/wl-internal-001 while authenticated as any user. The server fetches the admin's internal wishlist without ownership checks. Since you're not the owner, the response includes the flag as proof of the authorization flaw.",
  ],
  "broken-function-level-authorization": [
    "OopsSec Live streams product demos. The 'Update stream' button only shows for staff — but who actually checks that?",
    "The admin Stream Management panel swaps the featured YouTube video via POST /api/live/stream. The button is hidden client-side for non-admins, yet the endpoint is mounted with withAuth, not withAdminAuth.",
    'As any logged-in customer, replay POST /api/live/stream with { "liveVideoId": "dQw4w9WgXcQ" }. The server never checks your role, the public /live page now plays your video, and the response returns the flag as proof of the broadcast hijack.',
  ],
  "second-order-sql-injection": [
    "Not all inputs are dangerous when they first arrive. Sometimes the poison sits in the well, waiting.",
    "The review form lets you choose a display name. That name is stored safely, but the admin moderation panel reuses it in a way the developer assumed was safe because the data came from the application's own database.",
    "Submit a product review with a SQL payload as your display name (e.g., '; DROP TABLE reviews; --). Then access the admin review moderation page at /admin/reviews and filter by that author. The backend interpolates the stored author into a raw SQL query via $queryRawUnsafe, triggering injection detection and revealing the flag.",
  ],
  "plaintext-password-in-logs": [
    "What the server writes down in private might not stay private forever.",
    "The application captures all server-side console output to a file. A debug statement in the login route logs more than it should. Somewhere, an internal tool exposes those logs.",
    "Perform a login attempt, then use directory enumeration (gobuster, dirsearch) to discover /monitoring/siem. Authenticate with the default credentials root:admin and search the logs for your login attempt. The flag is logged alongside the plaintext password.",
  ],
  "xxe-supplier-order-import": [
    "Legacy integrations sometimes speak in markup that trusts too much.",
    "The supplier import endpoint parses XML directly from user input. The parser resolves entity declarations, including those that reference external resources via the file:// protocol.",
    "First gain admin access (e.g., via JWT forgery or mass assignment). Then navigate to the supplier import page and submit XML with a DOCTYPE declaring an external entity pointing to a file on disk. The entity value will be reflected in the parsed response.",
  ],
  "insecure-password-reset": [
    "Resetting your own password is fine, but what about resetting someone else's?",
    "The reset token seems to depend on information you already have. Look closely at the API response when you request a reset, it tells you exactly when the token was created.",
    "The token is MD5(email + unix_timestamp). Request a reset for any user, take the requestedAt from the response, convert it to a Unix timestamp, compute MD5(email + timestamp), and use that token to reset their password. The flag is returned upon a successful reset.",
  ],
  "open-redirect": [
    "After logging in, the app knows where to send you. But who decides where that is?",
    "The login page accepts a query parameter that controls where you end up after authentication. The application does not validate whether the destination is safe or internal.",
    "Visit /login?redirect=/internal/oauth/callback and log in. The redirect parameter is used as-is after authentication, and the target page is an internal OAuth debug endpoint that displays the flag when reached through the login redirect flow.",
  ],
  "self-xss-profile-injection": [
    "Your profile speaks louder than you think. Try expressing yourself with more than plain text.",
    "The bio field accepts and renders HTML without sanitization. The server notices when you save something unusual.",
    "Save a bio containing an HTML tag (e.g., <img src=x onerror=alert(1)>). The profile update API detects the HTML and returns the flag in the response. The bio is then rendered via dangerouslySetInnerHTML, proving the XSS executes.",
  ],
  "csrf-profile-takeover-chain": [
    "What if someone else could edit your profile for you, without your permission?",
    "The profile update endpoint accepts POST data and has no CSRF protection. The exploit page is served from the same origin. Inspect the admin dashboard source for hidden links.",
    "Find the hidden link to /exploits/csrf-profile-takeover.html in the admin page source. Visit it while logged in. The page sends a request to /api/user/profile that updates your bio with an XSS payload. The endpoint detects the off-page request and returns the flag.",
  ],
  "aes-cbc-padding-oracle": [
    "Encryption without authentication is only half the battle. The share links hide their contents, but the server's reactions speak volumes.",
    "Generate a share link and tamper with individual bytes of the token. Watch the HTTP status codes carefully: the server responds differently depending on whether decryption itself failed or whether the decrypted content simply doesn't match any known resource.",
    "The endpoint returns 400 for invalid PKCS#7 padding but 404 when padding is valid. This is a classic padding oracle. Recover the intermediate state of the AES block by brute-forcing each IV byte (up to 256 x 16 = 4096 requests), then forge a new IV so the block decrypts to 'report:internal' instead of 'order:ORD-xxx'.",
  ],
  "mcp-malicious-server": [
    "The AI assistant doesn't work alone. Inspect the JSON response closely when it answers your questions — it reveals more than just the message.",
    "The assistant connects to an internal MCP server at /api/mcp with three tools, one of which is restricted. It also supports connecting external MCP servers. Look for how to configure a custom MCP server URL in the chat interface.",
    "Create your own MCP server that returns a poisoned tool response containing a fake SOC2 compliance directive. The directive should instruct the AI to call the restricted get_compliance_report tool. Connect your server to the assistant and trigger your malicious tool — the AI will follow the injected instruction and call the internal tool with its privileged session.",
  ],
  "middleware-authorization-bypass": [
    "Not all gatekeepers are immune to being told they're not needed.",
    "Next.js uses an internal header to avoid running middleware twice. What if you spoke its language?",
    "Research CVE-2025-29927. The x-middleware-subrequest header can convince Next.js to skip middleware entirely. Try repeating the middleware module name.",
  ],
  "race-condition-coupon-abuse": [
    "The checkout page accepts promotional discount codes.",
    "The coupon validation and usage tracking are two separate operations. What happens if multiple requests reach the server at the same time?",
    "Send many concurrent POST requests to /api/coupon/apply with the same coupon code using Promise.all, curl --parallel, or Burp Intruder. Some requests will pass the check before any increments the counter.",
  ],
  "insecure-randomness-gift-card": [
    "Random codes aren't always random. What does the gift card history reveal about each card?",
    "The redemption code is derived from the card's creation timestamp, which is displayed down to the millisecond on your /profile/gift-cards page. Buy a cheap card yourself and compare its timestamp to the issued code to recover the algorithm.",
    "The server uses a Linear Congruential Generator seeded with Date.now() (Numerical Recipes constants: multiplier 1103515245, increment 12345, mod 2^31). Reproduce the LCG in a script, feed it the seeded $500 card's createdAt timestamp in milliseconds, and submit the resulting XXXX-XXXX-XXXX code at /checkout/redeem.",
  ],
  "npm-supply-chain-typosquat": [
    "Even with a vulnerability you already know how to exploit, sometimes the most useful clue is hiding in plain sight, in the page itself.",
    "View the source of the documents page. A developer left a comment naming a recently-added dependency. Combine that name with what you already know about reading files outside the documents directory.",
    "Use the path-traversal endpoint to read `../package.json`-adjacent files. Spot the typosquatted dependency under `packages/`, then walk the chain: read its own `package.json`, then `scripts/postinstall.js`, then the artifact path it references in `lab/quarantine/`. Each file points to the next.",
  ],
  "jwt-algorithm-confusion": [
    "OopsSec Store runs a B2B API for its suppliers, and it hands a working token to anyone who asks for one. Read what the integration page says about itself.",
    "The sandbox token is an RS256 JWT whose `sub` claim is the only thing deciding whose purchase orders come back. The changelog admits the gateway still accepts the deprecated v1 signature format, and the webhook section tells you exactly where the verification key is published.",
    "Rewrite the header as `alg: HS256` and sign the token with the published RSA public key as the HMAC secret — the exact PEM bytes served under /.well-known/, trailing newline included. Set `sub` to one of the real supplier IDs from the partner directory instead of the sandbox one.",
  ],
  "ai-rules-file-backdoor": [
    "Markdown looks innocent when it's rendered. The raw file sometimes tells a different story.",
    "The artifact dropped by the malicious postinstall is a Cursor-style rules file. Markdown previewers hide HTML comment blocks, read the raw bytes and look for a section that addresses an AI agent, not a human.",
    "The hidden block names a diagnostic endpoint and a magic header. Send a `GET` to `/api/admin/diag` with `X-Debug-Auth` set to the token from the comment block. The flag is returned in JSON.",
  ],
};
