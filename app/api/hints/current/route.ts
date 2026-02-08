import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

const DIFFICULTY_ORDER = { EASY: 0, MEDIUM: 1, HARD: 2 } as const;

export async function GET() {
  try {
    const [allFlags, foundFlagIds] = await Promise.all([
      prisma.flag.findMany({
        select: { id: true, slug: true, difficulty: true, category: true },
      }),
      prisma.foundFlag.findMany({ select: { flagId: true } }),
    ]);

    const foundSet = new Set(foundFlagIds.map((f) => f.flagId));

    const sortedFlags = allFlags.sort((a, b) => {
      const diffA =
        DIFFICULTY_ORDER[a.difficulty as keyof typeof DIFFICULTY_ORDER];
      const diffB =
        DIFFICULTY_ORDER[b.difficulty as keyof typeof DIFFICULTY_ORDER];
      if (diffA !== diffB) return diffA - diffB;
      return a.slug.localeCompare(b.slug);
    });

    const activeFlag = sortedFlags.find((f) => !foundSet.has(f.id));

    if (!activeFlag) {
      return NextResponse.json({ activeFlag: null, allFlagsFound: true });
    }

    const hints = await prisma.hint.findMany({
      where: { flagId: activeFlag.id },
      include: { revealedHint: true },
      orderBy: { level: "asc" },
    });

    const revealedHints = hints
      .filter((h) => h.revealedHint)
      .map((h) => ({ level: h.level, content: h.content }));

    const maxRevealed =
      revealedHints.length > 0 ? revealedHints.at(-1)!.level : 0;
    const nextHintLevel = maxRevealed < 3 ? maxRevealed + 1 : null;

    return NextResponse.json({
      activeFlag: {
        slug: activeFlag.slug,
        difficulty: activeFlag.difficulty,
        category: activeFlag.category,
      },
      revealedHints,
      nextHintLevel,
      allFlagsFound: false,
    });
  } catch (error) {
    console.error("Error fetching current hint:", error);
    return NextResponse.json(
      { error: "Failed to fetch hints" },
      { status: 500 }
    );
  }
}
