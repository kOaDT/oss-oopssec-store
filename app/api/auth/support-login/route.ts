import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { createWeakJWT } from "@/lib/server-auth";

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const token = searchParams.get("token");

    if (!token) {
      return NextResponse.json(
        { error: "Support access token is required" },
        { status: 400 }
      );
    }

    const supportToken = await prisma.supportAccessToken.findUnique({
      where: { token },
      include: {
        user: {
          select: {
            id: true,
            email: true,
            role: true,
          },
        },
      },
    });

    if (!supportToken) {
      return NextResponse.json(
        { error: "Invalid support access token" },
        { status: 401 }
      );
    }

    if (supportToken.expiresAt < new Date()) {
      return NextResponse.json(
        { error: "Support access token has expired" },
        { status: 401 }
      );
    }

    const authToken = createWeakJWT({
      id: supportToken.user.id,
      email: supportToken.user.email,
      role: supportToken.user.role,
      hint: "The secret is not so secret",
      exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 365,
      supportAccess: true,
    });

    return NextResponse.json({
      token: authToken,
      user: {
        id: supportToken.user.id,
        email: supportToken.user.email,
        role: supportToken.user.role,
      },
    });
  } catch (error) {
    console.error("Error during support login:", error);
    return NextResponse.json(
      { error: "Failed to authenticate with support token" },
      { status: 500 }
    );
  }
}
