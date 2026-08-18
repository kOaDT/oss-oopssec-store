import fs from "node:fs";
import path from "node:path";

export interface HallOfFameEntry {
  username: string;
  avatarUrl: string;
  githubUrl: string;
  date: string;
  country?: string;
}

/** GitHub's own rule: alphanumerics with single inner hyphens, 39 chars max.
 * The hyphen is matched with a lookahead rather than consumed alongside the
 * character after it, so each repetition costs exactly one character and the
 * bound is the 39 it claims to be. */
const USERNAME_PATTERN = /^[A-Za-z\d](?:[A-Za-z\d]|-(?=[A-Za-z\d])){0,38}$/;

/** Avatars are fetched by the runner at build time, so a pull request must not
 * be able to point that fetch at a host of its choosing. */
const AVATAR_HOST = "avatars.githubusercontent.com";

const PROFILE_ORIGIN = "https://github.com";

/**
 * `hall-of-fame/data.json` lives at the repository root, outside this Astro
 * project. Importing across the package boundary would pull the file into
 * `astro check`'s program, so it is read from disk instead — anchored on
 * whichever ancestor of the cwd actually holds it, since the build runs from
 * `docs/` under the npm scripts and CI but from the root under a bare
 * `astro build`.
 */
function resolveDataPath(): string {
  let dir = process.cwd();
  for (let depth = 0; depth < 4; depth += 1) {
    const candidate = path.join(dir, "hall-of-fame", "data.json");
    if (fs.existsSync(candidate)) return candidate;
    dir = path.dirname(dir);
  }
  throw new Error(
    `hall-of-fame/data.json: not found in any ancestor of ${process.cwd()}`
  );
}

/**
 * Badge files are named after the username, so two entries differing only in
 * case would silently overwrite each other on a case-insensitive filesystem.
 *
 * Mirrored by `badgeUrls()` in `lib/config.ts`, which builds the URLs the app
 * hands out; `tests/unit/hall-of-fame-badges.test.ts` holds the two together.
 */
export function badgeSlug(username: string): string {
  return username.toLowerCase();
}

/**
 * The `getStaticPaths` both badge routes share. Keeping it here means the two
 * routes cannot disagree on the slug, and neither has to cast `props` back to
 * an entry.
 */
export function badgeStaticPaths(): {
  params: { username: string };
  props: HallOfFameEntry;
}[] {
  return getHallOfFameEntries().map(entry => ({
    params: { username: badgeSlug(entry.username) },
    props: entry,
  }));
}

function assertValid(entry: unknown, index: number): HallOfFameEntry {
  const where = `hall-of-fame/data.json[${index}]`;
  if (typeof entry !== "object" || entry === null) {
    throw new Error(`${where}: expected an object`);
  }

  const { username, avatarUrl, githubUrl, date, country } = entry as Record<
    string,
    unknown
  >;

  if (typeof username !== "string" || !USERNAME_PATTERN.test(username)) {
    throw new Error(`${where}: "${username}" is not a valid GitHub username`);
  }
  if (typeof avatarUrl !== "string" || typeof githubUrl !== "string") {
    throw new Error(`${where}: avatarUrl and githubUrl must be strings`);
  }

  let avatar: URL;
  let profile: URL;
  try {
    avatar = new URL(avatarUrl);
    profile = new URL(githubUrl);
  } catch {
    throw new Error(`${where}: avatarUrl and githubUrl must be absolute URLs`);
  }
  if (avatar.protocol !== "https:" || avatar.host !== AVATAR_HOST) {
    throw new Error(`${where}: avatarUrl must be served by ${AVATAR_HOST}`);
  }
  if (profile.origin !== PROFILE_ORIGIN) {
    throw new Error(`${where}: githubUrl must point at ${PROFILE_ORIGIN}`);
  }

  if (typeof date !== "string" || Number.isNaN(Date.parse(date))) {
    throw new Error(`${where}: "${date}" is not a parsable date`);
  }
  if (country !== undefined && typeof country !== "string") {
    throw new Error(`${where}: country must be a string when present`);
  }

  return { username, avatarUrl, githubUrl, date, country };
}

/**
 * Validates parsed JSON. Split from the disk read so the rules that actually
 * matter — the avatar host allowlist, the username shape, the slug collision —
 * can be exercised against arbitrary input by
 * `tests/unit/hall-of-fame-badges.test.ts` without writing files.
 */
export function parseHallOfFame(raw: unknown): HallOfFameEntry[] {
  if (!Array.isArray(raw)) {
    throw new Error("hall-of-fame/data.json: expected an array");
  }

  const entries = raw.map(assertValid);

  const seen = new Map<string, string>();
  for (const { username } of entries) {
    const slug = badgeSlug(username);
    const previous = seen.get(slug);
    if (previous) {
      throw new Error(
        `hall-of-fame/data.json: "${username}" and "${previous}" collide on the badge slug "${slug}"`
      );
    }
    seen.set(slug, username);
  }

  return entries;
}

let cached: HallOfFameEntry[] | undefined;

/**
 * Every entry, validated. Anything malformed throws rather than degrading:
 * a bad entry would otherwise ship a broken badge under a real person's name,
 * and failing the build surfaces it while the pull request is still open.
 */
export function getHallOfFameEntries(): HallOfFameEntry[] {
  if (cached) return cached;

  cached = parseHallOfFame(
    JSON.parse(fs.readFileSync(resolveDataPath(), "utf8"))
  );
  return cached;
}
