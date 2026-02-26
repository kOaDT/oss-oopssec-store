import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { hashMD5 } from "@/lib/server-auth";

export async function POST(request: NextRequest) {
  try {
    const { email } = await request.json();

    if (!email) {
      return NextResponse.json({ error: "Email is required" }, { status: 400 });
    }

    const now = new Date();
    const requestedAt = now.toISOString();
    const timestamp = Math.floor(now.getTime() / 1000);

    const user = await prisma.user.findUnique({
      where: { email },
    });

    if (user) {
      const token = hashMD5(email + timestamp);

      const expiresAt = new Date(now.getTime() + 60 * 60 * 1000);

      await prisma.passwordResetToken.deleteMany({
        where: { email },
      });

      await prisma.passwordResetToken.create({
        data: {
          token,
          email,
          expiresAt,
        },
      });
    }

    return NextResponse.json({
      message:
        "If an account with that email exists, a password reset link has been sent.",
      requestedAt,
    });
  } catch {
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}
