import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

const DIFFICULTY_ORDER = { EASY: 0, MEDIUM: 1, HARD: 2 } as const;

export async function POST() {
  try {
    const [allFlags, foundFlagIds] = await Promise.all([
      prisma.flag.findMany({
        select: { id: true, slug: true, difficulty: true },
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
      return NextResponse.json(
        { error: "All flags have been found" },
        { status: 400 }
      );
    }

    const hints = await prisma.hint.findMany({
      where: { flagId: activeFlag.id },
      include: { revealedHint: true },
      orderBy: { level: "asc" },
    });

    const nextHint = hints.find((h) => !h.revealedHint);

    if (!nextHint) {
      return NextResponse.json(
        { error: "All hints for this flag have been revealed" },
        { status: 400 }
      );
    }

    await prisma.revealedHint.create({
      data: { hintId: nextHint.id },
    });

    const remainingUnrevealed = hints.filter(
      (h) => !h.revealedHint && h.id !== nextHint.id
    );
    const nextHintLevel =
      remainingUnrevealed.length > 0 ? remainingUnrevealed[0].level : null;

    return NextResponse.json({
      hint: { level: nextHint.level, content: nextHint.content },
      nextHintLevel,
    });
  } catch (error) {
    console.error("Error revealing hint:", error);
    return NextResponse.json(
      { error: "Failed to reveal hint" },
      { status: 500 }
    );
  }
}
