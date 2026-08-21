import { setTimeout as sleep } from "node:timers/promises";

/** The repository the stats card describes. Hardcoded rather than derived from
 * `SITE`: the docs site is the only thing in `SITE`, and a fork that renames it
 * should not silently start reporting this repository's numbers. */
const OWNER = "kOaDT";
const NAME = "oss-oopssec-store";

/** The slug the card prints under its title, so the image says which repository
 * it is describing wherever it is embedded. */
export const REPO_SLUG = `${OWNER}/${NAME}`;

const API = `https://api.github.com/repos/${REPO_SLUG}`;
const TIMEOUT_MS = 8_000;

/**
 * The contributors row draws everyone, so the list is paged through to the end
 * rather than truncated. The page cap is GitHub's own ceiling on the endpoint —
 * it stops enumerating at 500 contributors — so it bounds the loop without
 * cutting anything the API would have returned.
 */
const CONTRIBUTORS_PER_PAGE = 100;
const CONTRIBUTOR_PAGES = 5;

/** Half a year of weekly commit totals: long enough to show a trend, short
 * enough that each bar stays wide enough to read at README width. */
const ACTIVITY_WEEKS = 26;

/** GitHub warms the commit statistic in the background and answers 202 until it
 * is ready — which is what a repository that has not been asked in a while gets
 * on the first call of a deploy. Waiting it out costs eight seconds at worst and
 * nothing once the cache is warm, and the alternative is a card that silently
 * drops its sparkline whenever the deploy happens to be the caller that warmed
 * it. */
const ACTIVITY_ATTEMPTS = 5;
const ACTIVITY_RETRY_MS = 2_000;

export interface Contributor {
  login: string;
  /** Null when the API returned an entry without one. The card draws a
   * monogram in that case rather than dropping the contributor. */
  avatarUrl: string | null;
}

export interface RepoStats {
  /** Every human contributor GitHub will enumerate, most commits first. */
  contributors: Contributor[];
  /** Weekly commit totals, oldest first. Empty when GitHub was still computing
   * the statistic, which the template reads as "draw no sparkline". */
  commitsByWeek: number[];
}

interface ContributorPayload {
  login?: unknown;
  type?: unknown;
  avatar_url?: unknown;
}

/**
 * Degrading quietly is the point — the deploy must not fail because GitHub was
 * slow — but degrading silently is not. A card missing a band because the token
 * expired looks exactly like one that is simply up to date, and the daily
 * rebuild means it would keep looking that way until someone happened to
 * notice. The build still succeeds; the run log just says why the card is
 * short.
 */
function warn(path: string, reason: string): void {
  /* This module only ever runs during the Astro build, so the line lands in the
   * Actions log and never in a browser console. */
  // eslint-disable-next-line no-console
  console.warn(`[stats] GitHub ${path} unavailable: ${reason}`);
}

/**
 * The build runs unauthenticated locally and with the workflow's `GITHUB_TOKEN`
 * in CI. The token only lifts the rate limit — everything read here is public —
 * so a developer running `npm run build` gets the same card CI does, right up
 * until they hit the 60-per-hour anonymous ceiling and the card falls back to
 * the curriculum figures.
 */
async function ghFetch(path: string): Promise<Response | null> {
  const token = process.env.GITHUB_TOKEN;

  try {
    const response = await fetch(`${API}${path}`, {
      headers: {
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": `${REPO_SLUG} docs build`,
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });

    if (!response.ok) warn(path, `HTTP ${response.status}`);

    return response.ok ? response : null;
  } catch (error) {
    warn(path, error instanceof Error ? error.message : "network error");
    return null;
  }
}

async function json(response: Response | null): Promise<unknown> {
  if (!response) return null;
  try {
    return await response.json();
  } catch {
    return null;
  }
}

function count(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0
    ? Math.trunc(value)
    : 0;
}

/**
 * Every contributor, paged through in order.
 *
 * A short page is the end of the list, which is also what makes the length an
 * exact count: there is no total in the payload and no header to read it from,
 * so the only honest figure is the one that comes from having asked for all of
 * them. A page that fails mid-way ends the walk and keeps what came before,
 * because a partial row under a truthful count still reads correctly.
 */
async function fetchContributors(): Promise<Contributor[]> {
  const contributors: Contributor[] = [];

  for (let page = 1; page <= CONTRIBUTOR_PAGES; page += 1) {
    const listed = await json(
      await ghFetch(
        `/contributors?per_page=${CONTRIBUTORS_PER_PAGE}&page=${page}`
      )
    );
    if (!Array.isArray(listed)) break;

    for (const {
      login,
      type,
      avatar_url: url,
    } of listed as ContributorPayload[]) {
      /* Bots contribute to the graph but not to the row: the README invites
       * people to get their avatar onto it, which is not an invitation
       * dependabot can take up. Dropping them here also keeps the printed
       * figure honest, since it is the length of this list. */
      if (typeof login !== "string" || type === "Bot") continue;
      contributors.push({
        login,
        avatarUrl: typeof url === "string" ? url : null,
      });
    }

    if (listed.length < CONTRIBUTORS_PER_PAGE) break;
  }

  return contributors;
}

async function fetchCommitActivity(): Promise<number[]> {
  for (let attempt = 0; attempt < ACTIVITY_ATTEMPTS; attempt += 1) {
    const response = await ghFetch("/stats/commit_activity");
    if (!response) return [];

    if (response.status === 202) {
      if (attempt < ACTIVITY_ATTEMPTS - 1) await sleep(ACTIVITY_RETRY_MS);
      continue;
    }

    const weeks = await json(response);
    if (!Array.isArray(weeks)) return [];

    return weeks
      .slice(-ACTIVITY_WEEKS)
      .map(week => count((week as { total?: unknown })?.total));
  }

  warn(
    "/stats/commit_activity",
    `still computing after ${ACTIVITY_ATTEMPTS} attempts`
  );
  return [];
}

let cached: Promise<RepoStats> | undefined;

async function load(): Promise<RepoStats> {
  const [contributors, commitsByWeek] = await Promise.all([
    fetchContributors(),
    fetchCommitActivity(),
  ]);

  return { contributors, commitsByWeek };
}

/**
 * Everything the stats card needs from GitHub, fetched once for the whole
 * build. The two lists fail independently, so an endpoint that could not be
 * reached costs its own band and nothing else.
 *
 * Avatar images are deliberately not fetched here: the card decides how large
 * to draw them from how many there are, and the source resolution follows that
 * decision rather than leading it.
 *
 * An empty list is a rendering decision, not an error: the card is mostly built
 * from the curriculum, which is local data and always correct, so an
 * unreachable API costs a band rather than the docs deploy. Failing the build
 * here would mean a rate limit on the runner could block a walkthrough from
 * shipping.
 */
export default function getRepoStats(): Promise<RepoStats> {
  cached ??= load();
  return cached;
}
