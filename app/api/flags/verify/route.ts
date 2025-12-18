import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

export async function POST(request: Request) {
  try {
    const { flag } = await request.json();

    if (!flag || typeof flag !== "string") {
      return NextResponse.json(
        { error: "Flag is required", valid: false },
        { status: 400 }
      );
    }

    const foundFlag = await prisma.flag.findFirst({
      where: {
        flag: flag.trim(),
      },
    });

    if (!foundFlag) {
      return NextResponse.json({ valid: false });
    }

    return NextResponse.json({
      valid: true,
      slug: foundFlag.slug,
    });
  } catch (error) {
    console.error("Error verifying flag:", error);
    return NextResponse.json(
      { error: "Failed to verify flag", valid: false },
      { status: 500 }
    );
  }
}
