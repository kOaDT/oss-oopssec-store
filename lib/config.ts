export function getBaseUrl(): string {
  return process.env.NEXT_PUBLIC_BASE_URL || "http://localhost:3000";
}

const DOCS_SITE_URL = "https://koadt.github.io/oss-oopssec-store";
export const DOCS_BASE_URL = `${DOCS_SITE_URL}/posts`;
export const DOCS_ROADMAP_URL = `${DOCS_SITE_URL}/roadmap`;

export const GITHUB_REPO = "https://github.com/kOaDT/oss-oopssec-store";

/**
 * Tutorial-only flag used by the onboarding guide. It is intentionally NOT
 * stored in the database, so it never counts toward the real flag total,
 * the player's progress, or the Hall of Fame. The verify route short-circuits
 * on this exact value and returns `{ valid: true, tutorial: true }`.
 */
export const TUTORIAL_FLAG = "OSS{0ops_i_h4ck3d_1t}";
