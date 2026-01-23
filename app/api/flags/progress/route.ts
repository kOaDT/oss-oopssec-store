import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

export async function GET() {
  try {
    const [foundFlags, projectInit, totalFlags] = await Promise.all([
      prisma.foundFlag.findMany({
        include: {
          flag: {
            select: {
              slug: true,
            },
          },
        },
        orderBy: {
          foundAt: "asc",
        },
      }),
      prisma.projectInit.findFirst(),
      prisma.flag.count(),
    ]);

    return NextResponse.json({
      foundFlags: foundFlags.map((f) => ({
        slug: f.flag.slug,
        foundAt: f.foundAt.toISOString(),
      })),
      initializedAt: projectInit?.initializedAt.toISOString() ?? null,
      totalFlags,
    });
  } catch (error) {
    console.error("Error fetching progress:", error);
    return NextResponse.json(
      { error: "Failed to fetch progress" },
      { status: 500 }
    );
  }
}
