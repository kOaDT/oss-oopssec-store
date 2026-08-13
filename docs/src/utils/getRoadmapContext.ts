import {
  CURRICULUM,
  type Category,
  type Difficulty,
  type EstimatedMinutes,
} from "@/data/roadmap";
import { slugifyStr } from "./slugify";

export interface RoadmapEntry {
  /** `Flag.slug` in `prisma/flags.ts`. Unique across the curriculum. */
  slug: string;
  /** The blog post id. Two chained challenges may share one walkthrough. */
  walkthroughSlug: string;
  title: string;
  difficulty: Difficulty;
  category: Category;
  estimatedMinutes: EstimatedMinutes;
  /** Global challenge number (1-indexed across the whole curriculum) */
  number: number;
  chapterIndex: number;
  chapterTitle: string;
  chapterTagline: string;
  chapterSlug: string;
  prerequisites: number[];
}

export interface ChapterSummary {
  index: number;
  title: string;
  tagline: string;
  slug: string;
  /** Distinct walkthrough slugs in curriculum order */
  walkthroughSlugs: string[];
}

/* Flatten the curriculum once, mirroring the global numbering used by the
 * roadmap page (a running counter incremented per challenge). */
const entries: RoadmapEntry[] = [];
let counter = 0;
for (const [ci, chapter] of CURRICULUM.entries()) {
  const chapterSlug = slugifyStr(chapter.title);
  for (const challenge of chapter.challenges) {
    counter += 1;
    entries.push({
      slug: challenge.slug,
      walkthroughSlug: challenge.walkthroughSlug,
      title: challenge.title,
      difficulty: challenge.difficulty,
      category: challenge.category,
      estimatedMinutes: challenge.estimatedMinutes,
      number: counter,
      chapterIndex: ci + 1,
      chapterTitle: chapter.title,
      chapterTagline: chapter.tagline,
      chapterSlug,
      prerequisites: challenge.prerequisites ?? [],
    });
  }
}

/* A walkthrough can cover several challenges. Key on its first appearance for
 * metadata (number, title, chapter), but merge the prerequisites of every
 * challenge it covers so none are lost. */
const byWalkthrough = new Map<string, RoadmapEntry>();
for (const entry of entries) {
  const existing = byWalkthrough.get(entry.walkthroughSlug);
  if (!existing) {
    byWalkthrough.set(entry.walkthroughSlug, {
      ...entry,
      prerequisites: [...entry.prerequisites],
    });
  } else if (entry.prerequisites.length > 0) {
    const merged = new Set([...existing.prerequisites, ...entry.prerequisites]);
    existing.prerequisites = [...merged].sort((a, b) => a - b);
  }
}

const byNumber = new Map<number, RoadmapEntry>(
  entries.map(entry => [entry.number, entry])
);

/** Zero-padded challenge or chapter number, e.g. 7 -> "07". */
export const formatRoadmapNumber = (n: number): string =>
  String(n).padStart(2, "0");

export const chapterAnchorId = (index: number): string =>
  `chapter-${formatRoadmapNumber(index)}`;

export const challengeAnchorId = (number: number): string =>
  `challenge-${formatRoadmapNumber(number)}`;

/** Every challenge in curriculum order, one entry per challenge. */
export const getChallenges = (): RoadmapEntry[] => [...entries];

/** Looks up a challenge by the id of the blog post documenting it. */
export const getRoadmapContext = (
  walkthroughSlug: string
): RoadmapEntry | null => byWalkthrough.get(walkthroughSlug) ?? null;

/** Every challenge a walkthrough covers, in curriculum order. Almost always
 * one; a chained pair shares a single post. Use this over `getRoadmapContext`
 * wherever the output is per-challenge rather than per-page — that one collapses
 * a chain to its first link, which is right for a heading and wrong for
 * anything a reader of the second half has to act on. */
export const getWalkthroughChallenges = (
  walkthroughSlug: string
): RoadmapEntry[] =>
  entries.filter(entry => entry.walkthroughSlug === walkthroughSlug);

export const getNext = (number: number): RoadmapEntry | null =>
  byNumber.get(number + 1) ?? null;

export const resolveChallenges = (
  numbers: number[]
): Pick<RoadmapEntry, "number" | "title" | "walkthroughSlug">[] =>
  numbers
    .map(n => byNumber.get(n))
    .filter((entry): entry is RoadmapEntry => entry != null)
    .map(({ number, title, walkthroughSlug }) => ({
      number,
      title,
      walkthroughSlug,
    }));

/** One entry per distinct walkthrough in the same chapter, excluding the
 * walkthrough passed in. */
export const getChapterSiblings = (walkthroughSlug: string): RoadmapEntry[] => {
  const current = byWalkthrough.get(walkthroughSlug);
  if (!current) return [];
  const seen = new Set<string>([walkthroughSlug]);
  const siblings: RoadmapEntry[] = [];
  for (const entry of entries) {
    if (entry.chapterIndex !== current.chapterIndex) continue;
    if (seen.has(entry.walkthroughSlug)) continue;
    seen.add(entry.walkthroughSlug);
    siblings.push(entry);
  }
  return siblings;
};

export const getChapters = (): ChapterSummary[] =>
  CURRICULUM.map((chapter, ci) => {
    const walkthroughSlugs: string[] = [];
    const seen = new Set<string>();
    for (const challenge of chapter.challenges) {
      if (seen.has(challenge.walkthroughSlug)) continue;
      seen.add(challenge.walkthroughSlug);
      walkthroughSlugs.push(challenge.walkthroughSlug);
    }
    return {
      index: ci + 1,
      title: chapter.title,
      tagline: chapter.tagline,
      slug: slugifyStr(chapter.title),
      walkthroughSlugs,
    };
  });

export const getChapterBySlug = (slug: string): ChapterSummary | null =>
  getChapters().find(chapter => chapter.slug === slug) ?? null;
