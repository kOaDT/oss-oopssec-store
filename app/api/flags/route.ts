import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { logger } from "@/lib/logger";

export async function GET() {
  try {
    const flags = await prisma.flag.findMany({
      orderBy: {
        slug: "asc",
      },
    });

    return NextResponse.json(flags);
  } catch (error) {
    logger.error({ err: error, route: "/api/flags" }, "Error fetching flags");
    return NextResponse.json(
      { error: "Failed to fetch flags" },
      { status: 500 }
    );
  }
}
