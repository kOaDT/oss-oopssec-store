import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getAuthenticatedUser } from "@/lib/server-auth";
import crypto from "crypto";

const TOKEN_EXPIRY_DAYS = 365;

function generateSecureToken(): string {
  return crypto.randomBytes(32).toString("hex");
}

export async function GET(request: NextRequest) {
  try {
    const user = await getAuthenticatedUser(request);

    if (!user) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const supportToken = await prisma.supportAccessToken.findFirst({
      where: {
        userId: user.id,
        revoked: false,
      },
      orderBy: { createdAt: "desc" },
    });

    if (!supportToken) {
      return NextResponse.json({ supportToken: null });
    }

    return NextResponse.json({
      supportToken: {
        id: supportToken.id,
        token: supportToken.token,
        email: supportToken.email,
        expiresAt: supportToken.expiresAt,
        createdAt: supportToken.createdAt,
        revoked: supportToken.revoked,
      },
    });
  } catch (error) {
    console.error("Error fetching support token:", error);
    return NextResponse.json(
      { error: "Failed to fetch support access token" },
      { status: 500 }
    );
  }
}

export async function POST(request: NextRequest) {
  try {
    const user = await getAuthenticatedUser(request);

    if (!user) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const body = await request.json().catch(() => ({}));

    const targetEmail = body.email || user.email;

    const targetUser = await prisma.user.findUnique({
      where: { email: targetEmail },
      select: { id: true, email: true, role: true },
    });

    if (!targetUser) {
      return NextResponse.json({ error: "User not found" }, { status: 404 });
    }

    const token = generateSecureToken();
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + TOKEN_EXPIRY_DAYS);

    const supportToken = await prisma.supportAccessToken.create({
      data: {
        token,
        userId: targetUser.id,
        email: targetUser.email,
        expiresAt,
      },
    });

    return NextResponse.json({
      supportToken: {
        id: supportToken.id,
        token: supportToken.token,
        email: supportToken.email,
        expiresAt: supportToken.expiresAt,
        createdAt: supportToken.createdAt,
      },
      supportLoginUrl: `/support-login?token=${supportToken.token}`,
    });
  } catch (error) {
    console.error("Error creating support token:", error);
    return NextResponse.json(
      { error: "Failed to create support access token" },
      { status: 500 }
    );
  }
}

export async function DELETE(request: NextRequest) {
  try {
    const user = await getAuthenticatedUser(request);

    if (!user) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    await prisma.supportAccessToken.updateMany({
      where: {
        userId: user.id,
        revoked: false,
      },
      data: {
        revoked: true,
      },
    });

    return NextResponse.json({
      message: "Support access revoked successfully",
    });
  } catch (error) {
    console.error("Error revoking support token:", error);
    return NextResponse.json(
      { error: "Failed to revoke support access" },
      { status: 500 }
    );
  }
}
