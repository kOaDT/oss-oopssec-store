import type { APIRoute } from "astro";
import { getCollection } from "astro:content";
import { SITE } from "@/config";
import {
  CHALLENGES_BY_DIFFICULTY,
  TOTAL_CHALLENGES,
  type Category,
  type Difficulty,
} from "@/data/roadmap";
import { getPath } from "@/utils/getPath";
import {
  challengeAnchorId,
  chapterAnchorId,
  getChallenges,
} from "@/utils/getRoadmapContext";
import postFilter from "@/utils/postFilter";

/** Bump on any breaking change to the payload shape below. */
const FEED_VERSION = 1;

interface FeedWalkthrough {
  slug: string;
  title: string;
  description: string;
  url: string;
}

interface FeedChapter {
  index: number;
  title: string;
  tagline: string;
  url: string;
}

interface FeedChallenge {
  number: number;
  title: string;
  difficulty: Difficulty;
  /** Matches the app's `FlagCategory` enum, so this joins with `/api/flags`. */
  category: Category;
  /** Hands-on minutes to expect. A null `max` means open-ended. */
  estimatedMinutes: { min: number; max: number | null };
  url: string;
  chapter: FeedChapter;
  prerequisites: number[];
  /** Null while the walkthrough is unwritten, a draft, or still scheduled. */
  walkthrough: FeedWalkthrough | null;
}

interface ChallengeFeed {
  version: number;
  generatedAt: string;
  site: string;
  roadmapUrl: string;
  totalChallenges: number;
  challengesByDifficulty: Record<Difficulty, number>;
  challenges: FeedChallenge[];
}

export const GET: APIRoute = async ({ site }) => {
  const origin = site ?? new URL(SITE.website);
  const absolute = (path: string) => new URL(path, origin).href;

  const base = import.meta.env.BASE_URL.replace(/\/$/, "");
  const roadmapUrl = absolute(`${base}/roadmap`);

  const allPosts = await getCollection("blog");
  const walkthroughs = new Map<string, FeedWalkthrough>(
    allPosts.filter(postFilter).map(({ id, filePath, data }) => [
      id,
      {
        slug: id,
        title: data.title,
        description: data.description,
        url: absolute(getPath(id, filePath)),
      },
    ])
  );

  /* A walkthroughSlug matching no post at all is a rename or a deletion, not a
   * draft: it would ship a null into a public artifact and 404 the matching
   * roadmap link. Fail the build rather than let it through silently. Posts
   * that exist but are filtered out (draft, scheduled) stay a legitimate null. */
  const known = new Set(allPosts.map(({ id }) => id));
  const orphans = [
    ...new Set(
      getChallenges()
        .map(({ slug }) => slug)
        .filter(slug => !known.has(slug))
    ),
  ];
  if (orphans.length > 0) {
    throw new Error(
      `challenges.json: no walkthrough post found for ${orphans.join(", ")} — ` +
        `check walkthroughSlug in src/data/roadmap.ts`
    );
  }

  const feed: ChallengeFeed = {
    version: FEED_VERSION,
    generatedAt: new Date().toISOString(),
    site: origin.href,
    roadmapUrl,
    totalChallenges: TOTAL_CHALLENGES,
    challengesByDifficulty: CHALLENGES_BY_DIFFICULTY,
    challenges: getChallenges().map(entry => ({
      number: entry.number,
      title: entry.title,
      difficulty: entry.difficulty,
      category: entry.category,
      estimatedMinutes: {
        min: entry.estimatedMinutes[0],
        max: entry.estimatedMinutes[1],
      },
      url: `${roadmapUrl}#${challengeAnchorId(entry.number)}`,
      chapter: {
        index: entry.chapterIndex,
        title: entry.chapterTitle,
        tagline: entry.chapterTagline,
        url: `${roadmapUrl}#${chapterAnchorId(entry.chapterIndex)}`,
      },
      prerequisites: entry.prerequisites,
      walkthrough: walkthroughs.get(entry.slug) ?? null,
    })),
  };

  return new Response(JSON.stringify(feed), {
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
};
