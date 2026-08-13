import { CURRICULUM } from "@/docs/src/data/roadmap";
import { GITHUB_DISCUSSIONS } from "./config";
import { formatSlug } from "./format";

/**
 * Deep links into GitHub Discussions, prefilled for one challenge.
 *
 * Kept out of `lib/config.ts` on purpose: config is imported by a dozen client
 * components, and pulling the whole curriculum in behind it would ship 36
 * challenge records to the browser for no reason. Only Server Components need
 * this module.
 *
 * `docs/src/data/roadmap.ts` is the source of truth for challenge titles, and
 * the same file the docs site renders. The app has to read it rather than
 * derive a title from the slug, otherwise the two entry points name the same
 * challenge differently and threads stop lining up. The docs site keeps its own
 * copy of this logic in `docs/src/constants.ts`: it is a separate package and
 * cannot import from here.
 *
 * This import is the one thing the app pulls out of `docs/`, which the Docker
 * image otherwise excludes wholesale — see the exception in `.dockerignore`.
 */
const TITLES = new Map(
  CURRICULUM.flatMap((chapter) => chapter.challenges).map(
    ({ slug, title }) => [slug, title] as const
  )
);

/**
 * The curriculum title for a challenge. The parity suite asserts that roadmap
 * slugs and flag slugs match exactly, so the fallback should never fire — it is
 * there so a half-added challenge degrades to an ugly title instead of a blank
 * link.
 */
export function challengeTitle(slug: string): string {
  return TITLES.get(slug) ?? formatSlug(slug);
}

/**
 * "Stuck on a challenge" thread, prefilled for one challenge. A player who is
 * stuck is inside the app, not on GitHub, so the link carries everything the
 * form would otherwise ask twice.
 *
 * `category` is the slug GitHub derives from the category name: rename the
 * category on the repo and this link silently falls back to the generic picker.
 *
 * `title` is the only field GitHub prefills on a discussion form — the
 * per-field query params that work on issue forms are ignored here, and a
 * dropdown fed one lands on its first option rather than on the requested
 * value, which tags the thread with the wrong challenge. So the challenge name
 * travels in the title, and the form asks for it in a plain input.
 *
 * The other categories are reachable from the Discussions landing page and from
 * `.github/ISSUE_TEMPLATE/config.yml`; only this one is worth a deep link from
 * inside a challenge.
 */
export function askAboutChallengeUrl(slug: string): string {
  const params = new URLSearchParams({
    category: "stuck-on-a-challenge",
    title: `[Stuck] ${challengeTitle(slug)}`,
  });
  return `${GITHUB_DISCUSSIONS}/new?${params}`;
}
