import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { logger } from "@/lib/logger";

export async function GET() {
  try {
    const count = await prisma.flag.count();
    return NextResponse.json({ count });
  } catch (error) {
    logger.error(
      { err: error, route: "/api/flags/count" },
      "Error fetching flag count"
    );
    return NextResponse.json(
      { error: "Failed to fetch flag count" },
      { status: 500 }
    );
  }
}
