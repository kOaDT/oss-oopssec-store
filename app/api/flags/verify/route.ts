import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { logger } from "@/lib/logger";

export async function POST(request: Request) {
  try {
    const { flag } = await request.json();

    if (!flag || typeof flag !== "string") {
      return NextResponse.json(
        { error: "Flag is required", valid: false },
        { status: 400 }
      );
    }

    const matchedFlag = await prisma.flag.findFirst({
      where: {
        flag: flag.trim(),
      },
    });

    if (!matchedFlag) {
      return NextResponse.json({ valid: false });
    }

    const existingFoundFlag = await prisma.foundFlag.findUnique({
      where: {
        flagId: matchedFlag.id,
      },
    });

    if (existingFoundFlag) {
      return NextResponse.json({
        valid: true,
        slug: matchedFlag.slug,
        alreadyFound: true,
        foundAt: existingFoundFlag.foundAt.toISOString(),
      });
    }

    const newFoundFlag = await prisma.foundFlag.create({
      data: {
        flagId: matchedFlag.id,
      },
    });

    return NextResponse.json({
      valid: true,
      slug: matchedFlag.slug,
      alreadyFound: false,
      foundAt: newFoundFlag.foundAt.toISOString(),
    });
  } catch (error) {
    logger.error(
      { err: error, route: "/api/flags/verify" },
      "Error verifying flag"
    );
    return NextResponse.json(
      { error: "Failed to verify flag", valid: false },
      { status: 500 }
    );
  }
}
