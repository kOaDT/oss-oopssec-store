import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { hashMD5 } from "@/lib/server-auth";
import { parseBody } from "@/lib/validation";
import { resetPasswordBodySchema } from "@/lib/validation/schemas/auth";

export async function POST(request: NextRequest) {
  try {
    const parsed = await parseBody(request, resetPasswordBodySchema);
    if (!parsed.success) return parsed.response;
    const { token, password } = parsed.data;

    const resetToken = await prisma.passwordResetToken.findUnique({
      where: { token },
    });

    if (!resetToken) {
      return NextResponse.json(
        { error: "Invalid or expired reset token" },
        { status: 400 }
      );
    }

    if (resetToken.used) {
      return NextResponse.json(
        { error: "This reset token has already been used" },
        { status: 400 }
      );
    }

    if (resetToken.expiresAt < new Date()) {
      return NextResponse.json(
        { error: "This reset token has expired" },
        { status: 400 }
      );
    }

    const user = await prisma.user.findUnique({
      where: { email: resetToken.email },
    });

    if (!user) {
      return NextResponse.json({ error: "User not found" }, { status: 400 });
    }

    const hashedPassword = hashMD5(password);

    await prisma.user.update({
      where: { id: user.id },
      data: { password: hashedPassword },
    });

    await prisma.passwordResetToken.update({
      where: { id: resetToken.id },
      data: { used: true },
    });

    const response: { message: string; flag?: string } = {
      message: "Your password has been reset successfully.",
    };

    const flag = await prisma.flag.findUnique({
      where: { slug: "insecure-password-reset" },
    });

    if (flag) {
      response.flag = flag.flag;
    }

    return NextResponse.json(response);
  } catch {
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}
