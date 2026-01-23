import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

export async function GET() {
  try {
    const [foundFlags, projectInit, totalFlags, allFlags] = await Promise.all([
      prisma.foundFlag.findMany({
        include: {
          flag: {
            select: {
              slug: true,
              category: true,
              difficulty: true,
              cve: true,
              walkthroughSlug: true,
            },
          },
        },
        orderBy: {
          foundAt: "asc",
        },
      }),
      prisma.projectInit.findFirst(),
      prisma.flag.count(),
      prisma.flag.findMany({
        select: {
          category: true,
          difficulty: true,
        },
      }),
    ]);

    const statsByCategory = allFlags.reduce(
      (acc, flag) => {
        acc[flag.category] = (acc[flag.category] || 0) + 1;
        return acc;
      },
      {} as Record<string, number>
    );

    const statsByDifficulty = allFlags.reduce(
      (acc, flag) => {
        acc[flag.difficulty] = (acc[flag.difficulty] || 0) + 1;
        return acc;
      },
      {} as Record<string, number>
    );

    return NextResponse.json({
      foundFlags: foundFlags.map((f) => ({
        slug: f.flag.slug,
        category: f.flag.category,
        difficulty: f.flag.difficulty,
        cve: f.flag.cve,
        walkthroughSlug: f.flag.walkthroughSlug,
        foundAt: f.foundAt.toISOString(),
      })),
      initializedAt: projectInit?.initializedAt.toISOString() ?? null,
      totalFlags,
      statsByCategory,
      statsByDifficulty,
    });
  } catch (error) {
    console.error("Error fetching progress:", error);
    return NextResponse.json(
      { error: "Failed to fetch progress" },
      { status: 500 }
    );
  }
}
