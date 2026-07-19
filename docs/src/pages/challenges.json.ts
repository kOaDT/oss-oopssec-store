import type { APIRoute } from "astro";
import { getCollection } from "astro:content";
import { SITE } from "@/config";
import {
  CHALLENGES_BY_DIFFICULTY,
  TOTAL_CHALLENGES,
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

  const posts = await getCollection("blog", postFilter);
  const walkthroughs = new Map<string, FeedWalkthrough>(
    posts.map(({ id, filePath, data }) => [
      id,
      {
        slug: id,
        title: data.title,
        description: data.description,
        url: absolute(getPath(id, filePath)),
      },
    ])
  );

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
