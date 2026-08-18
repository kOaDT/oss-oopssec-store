export function getBaseUrl(): string {
  return process.env.NEXT_PUBLIC_BASE_URL || "http://localhost:3000";
}

const DOCS_SITE_URL = "https://koadt.github.io/oss-oopssec-store";
export const DOCS_BASE_URL = `${DOCS_SITE_URL}/posts`;
export const DOCS_ROADMAP_URL = `${DOCS_SITE_URL}/roadmap`;

/**
 * Hall of Fame badges, rendered at docs build time from `hall-of-fame/data.json`
 * and served as static files off GitHub Pages. A badge only exists once the
 * entry has been merged, which is the whole of its verification — nothing here
 * reads the player's local progress, and nothing could: that database never
 * leaves their machine. `.svg` is the inline pill, `.png` the social card.
 *
 * Keep the slug in step with `badgeSlug()` in `docs/src/utils/getHallOfFame.ts`
 * — `tests/unit/hall-of-fame-badges.test.ts` fails if the two ever diverge.
 *
 * The slug is encoded even though the docs build rejects any username that
 * would need it: this runs against whatever the local database holds, and a
 * stray character has to break the URL rather than the surrounding markup of
 * the snippet the panel hands the player.
 */
export function badgeUrls(username: string) {
  const base = `${DOCS_SITE_URL}/badges/${encodeURIComponent(username.toLowerCase())}`;
  return { pill: `${base}.svg`, card: `${base}.png` };
}

export const GITHUB_REPO_SLUG = "kOaDT/oss-oopssec-store";
export const GITHUB_REPO = `https://github.com/${GITHUB_REPO_SLUG}`;
export const GITHUB_DISCUSSIONS = `${GITHUB_REPO}/discussions`;

export const DEV_TO_URL = "https://dev.to/oopssec-store";
export const MEDIUM_URL = "https://medium.com/@oopssec-store";

/**
 * TryHackMe walkthrough room built on top of this lab.
 */
export const THM_ROOM_URL =
  "https://tryhackme.com/jr/oopssecstorethesummeraudit";

/** Cache TTL (in seconds) for the GitHub-backed contributors list. */
export const CONTRIBUTORS_REVALIDATE_SECONDS = 86_400;

/**
 * Tutorial-only flag used by the onboarding guide. It is intentionally NOT
 * stored in the database, so it never counts toward the real flag total,
 * the player's progress, or the Hall of Fame. The verify route short-circuits
 * on this exact value and returns `{ valid: true, tutorial: true }`.
 */
export const TUTORIAL_FLAG = "OSS{0ops_i_h4ck3d_1t}";
