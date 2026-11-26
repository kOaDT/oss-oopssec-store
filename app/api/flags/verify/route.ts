import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { logger } from "@/lib/logger";
import { parseBody } from "@/lib/validation";
import { verifyFlagBodySchema } from "@/lib/validation/schemas/flags";
import { TUTORIAL_FLAG } from "@/lib/config";

const isUniqueViolation = (error: unknown) =>
  typeof error === "object" &&
  error !== null &&
  "code" in error &&
  error.code === "P2002";

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

    const findFoundFlag = () =>
      prisma.foundFlag.findUnique({
        where: {
          flagId: matchedFlag.id,
        },
      });

    const alreadyFound = (foundAt: Date) =>
      NextResponse.json({
        valid: true,
        slug: matchedFlag.slug,
        alreadyFound: true,
        foundAt: foundAt.toISOString(),
      });

    const existingFoundFlag = await findFoundFlag();

    if (existingFoundFlag) {
      return alreadyFound(existingFoundFlag.foundAt);
    }

    let newFoundFlag;
    try {
      newFoundFlag = await prisma.foundFlag.create({
        data: {
          flagId: matchedFlag.id,
        },
      });
    } catch (error) {
      // A concurrent submission of the same flag can pass the lookup above
      // too; the unique index on flagId lets only one insert through.
      if (!isUniqueViolation(error)) throw error;
      const recorded = await findFoundFlag();
      if (!recorded) throw error;
      return alreadyFound(recorded.foundAt);
    }

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
