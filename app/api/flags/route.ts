import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { logger } from "@/lib/logger";

/**
 * Public challenge catalogue.
 *
 * The `flag` value is the one thing a player is meant to earn, so it is only
 * serialized for challenges already recorded in `found_flags`; every other
 * entry carries `flag: null`. Withholding it here rather than in the UI is what
 * keeps unsolved values off the wire — a client-side check ships them to the
 * browser and merely hides them.
 *
 * The field list is explicit on purpose: a spread would silently publish any
 * column later added to `Flag`.
 */
export async function GET() {
  try {
    const flags = await prisma.flag.findMany({
      orderBy: {
        slug: "asc",
      },
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

    return NextResponse.json(
      flags.map(({ foundFlag, flag, ...rest }) => ({
        ...rest,
        flag: foundFlag ? flag : null,
      }))
    );
  } catch (error) {
    logger.error({ err: error, route: "/api/flags" }, "Error fetching flags");
    return NextResponse.json(
      { error: "Failed to fetch flags" },
      { status: 500 }
    );
  }
}
