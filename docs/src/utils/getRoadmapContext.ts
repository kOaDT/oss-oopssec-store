import { CURRICULUM, type Difficulty } from "@/data/roadmap";
import { slugifyStr } from "./slugify";

export interface RoadmapEntry {
  /** walkthroughSlug, which equals the blog post id */
  slug: string;
  title: string;
  difficulty: Difficulty;
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
  slugs: string[];
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
      slug: challenge.walkthroughSlug,
      title: challenge.title,
      difficulty: challenge.difficulty,
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
const bySlug = new Map<string, RoadmapEntry>();
for (const entry of entries) {
  const existing = bySlug.get(entry.slug);
  if (!existing) {
    bySlug.set(entry.slug, {
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

export const getRoadmapContext = (slug: string): RoadmapEntry | null =>
  bySlug.get(slug) ?? null;

export const getNext = (number: number): RoadmapEntry | null =>
  byNumber.get(number + 1) ?? null;

export const resolveChallenges = (
  numbers: number[]
): Pick<RoadmapEntry, "number" | "title" | "slug">[] =>
  numbers
    .map(n => byNumber.get(n))
    .filter((entry): entry is RoadmapEntry => entry != null)
    .map(({ number, title, slug }) => ({ number, title, slug }));

/** Distinct walkthrough slugs in the same chapter, excluding `slug`. */
export const getChapterSiblings = (slug: string): RoadmapEntry[] => {
  const current = bySlug.get(slug);
  if (!current) return [];
  const seen = new Set<string>([slug]);
  const siblings: RoadmapEntry[] = [];
  for (const entry of entries) {
    if (entry.chapterIndex !== current.chapterIndex) continue;
    if (seen.has(entry.slug)) continue;
    seen.add(entry.slug);
    siblings.push(entry);
  }
  return siblings;
};

export const getChapters = (): ChapterSummary[] =>
  CURRICULUM.map((chapter, ci) => {
    const slugs: string[] = [];
    const seen = new Set<string>();
    for (const challenge of chapter.challenges) {
      if (seen.has(challenge.walkthroughSlug)) continue;
      seen.add(challenge.walkthroughSlug);
      slugs.push(challenge.walkthroughSlug);
    }
    return {
      index: ci + 1,
      title: chapter.title,
      tagline: chapter.tagline,
      slug: slugifyStr(chapter.title),
      slugs,
    };
  });

export const getChapterBySlug = (slug: string): ChapterSummary | null =>
  getChapters().find(chapter => chapter.slug === slug) ?? null;
