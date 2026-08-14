import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { logger } from "@/lib/logger";

export async function GET(
  request: Request,
  { params }: { params: Promise<{ slug: string }> }
) {
  try {
    const { slug } = await params;

    // Same contract as GET /api/flags: explicit field list, and the value only
    // once the challenge is solved. The metadata is what the vulnerability
    // page renders.
    const record = await prisma.flag.findUnique({
      where: { slug },
      select: {
        id: true,
        flag: true,
        slug: true,
        cve: true,
        cwe: true,
        owasp: true,
        markdownFile: true,
        walkthroughSlug: true,
        category: true,
        difficulty: true,
        foundFlag: { select: { id: true } },
      },
    });

    if (!record) {
      return NextResponse.json({ error: "Flag not found" }, { status: 404 });
    }

    const { foundFlag, flag, ...rest } = record;

    return NextResponse.json({ ...rest, flag: foundFlag ? flag : null });
  } catch (error) {
    logger.error(
      { err: error, route: "/api/flags/[slug]" },
      "Error fetching flag"
    );
    return NextResponse.json(
      { error: "Failed to fetch flag" },
      { status: 500 }
    );
  }
}
