import { getCollection } from "astro:content";
import {
  CHALLENGES_BY_DIFFICULTY,
  CURRICULUM,
  TOTAL_CHALLENGES,
} from "@/data/roadmap";
import statsCard, { avatarLayout } from "./badge-templates/stats";
import { fetchAvatarDataUris } from "./fetchAvatarDataUri";
import { getHallOfFameEntries } from "./getHallOfFame";
import getRepoStats, { REPO_SLUG, type Contributor } from "./getRepoStats";
import { getChallenges } from "./getRoadmapContext";
import postFilter from "./postFilter";
import { svgBufferToPngBuffer } from "./svgToPng";

interface DrawnContributor {
  login: string;
  avatar: string | null;
}

/**
 * The contributors row, with each avatar fetched at twice the size it will be
 * drawn at so the circles stay sharp once the card is rasterised. The layout
 * decides that size from how many contributors there are, which is why the
 * images cannot be fetched alongside the rest of the GitHub data.
 */
async function drawnContributors(
  contributors: Contributor[]
): Promise<DrawnContributor[]> {
  const { size } = avatarLayout(contributors.length);

  const avatars = await fetchAvatarDataUris(
    contributors.map(({ avatarUrl }) => avatarUrl),
    size * 2
  );

  return contributors.map(({ login }, index) => ({
    login,
    avatar: avatars[index],
  }));
}

/**
 * How many of the curriculum's walkthroughs are actually readable today.
 *
 * Not the number of posts in the collection, and not the number of challenges:
 * a walkthrough can cover more than one challenge, and a post that is still a
 * draft or scheduled is not published yet. Counting the distinct slugs that
 * resolve to a post `postFilter` lets through is the only figure that matches
 * what a reader can click on, which is the same rule `challenges.json` applies.
 */
async function publishedWalkthroughs(): Promise<number> {
  const published = new Set(
    (await getCollection("blog")).filter(postFilter).map(({ id }) => id)
  );

  return new Set(
    getChallenges()
      .map(({ walkthroughSlug }) => walkthroughSlug)
      .filter(slug => published.has(slug))
  ).size;
}

/**
 * The card, as the SVG satori produced.
 *
 * Both halves of the data are gathered here rather than in the template: the
 * curriculum figures come from the same module the roadmap page and
 * `challenges.json` read, so the card cannot drift from what the site says
 * everywhere else, and the GitHub figures arrive already degraded to empty
 * lists if the API was unreachable.
 */
async function build(): Promise<string> {
  const stats = await getRepoStats();

  return statsCard({
    totalChallenges: TOTAL_CHALLENGES,
    chapters: CURRICULUM.length,
    walkthroughs: await publishedWalkthroughs(),
    byDifficulty: CHALLENGES_BY_DIFFICULTY,
    hallOfFame: getHallOfFameEntries().length,
    repoUrl: `github.com/${REPO_SLUG}`,
    stats,
    contributors: await drawnContributors(stats.contributors),
  });
}

let card: Promise<string> | undefined;

/**
 * The card, rendered once per build.
 *
 * Both endpoints draw the same image, and without this the second one re-reads
 * the collection, re-downloads every avatar and re-runs satori for a result
 * that is already on disk.
 */
function render(): Promise<string> {
  card ??= build();
  return card;
}

/** Self-contained: satori draws glyphs as paths and the avatars travel as data
 * URIs, so nothing is fetched when the card is displayed. */
export function generateStatsSvg(): Promise<string> {
  return render();
}

/** The same card rasterised, for the places that reject an SVG. */
export async function generateStatsPng(): Promise<Uint8Array<ArrayBuffer>> {
  return svgBufferToPngBuffer(await render());
}
