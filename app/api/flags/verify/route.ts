import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { logger } from "@/lib/logger";
import { parseBody } from "@/lib/validation";
import { verifyFlagBodySchema } from "@/lib/validation/schemas/flags";
import { TUTORIAL_FLAG } from "@/lib/config";

export async function POST(request: Request) {
  try {
    const parsed = await parseBody(request, verifyFlagBodySchema);
    if (!parsed.success) return parsed.response;
    const { flag } = parsed.data;

    // Onboarding practice flag: accepted without touching the database, so it
    // never affects the flag count, progress, or the Hall of Fame.
    if (flag.trim() === TUTORIAL_FLAG) {
      return NextResponse.json({ valid: true, tutorial: true });
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
