import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { withAuth } from "@/lib/server-auth";
import crypto from "crypto";
import { logger } from "@/lib/logger";
import { parseBody } from "@/lib/validation";
import { createSupportAccessBodySchema } from "@/lib/validation/schemas/user";

const TOKEN_EXPIRY_DAYS = 365;

function generateSecureToken(): string {
  return crypto.randomBytes(32).toString("hex");
}

export const GET = withAuth(async (_request, _context, user) => {
  try {
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
    logger.error(
      { err: error, route: "/api/user/support-access" },
      "Error fetching support token"
    );
    return NextResponse.json(
      { error: "Failed to fetch support access token" },
      { status: 500 }
    );
  }
});

export const POST = withAuth(async (request: NextRequest, _context, user) => {
  try {
    const parsed = await parseBody(request, createSupportAccessBodySchema, {
      allowEmptyBody: true,
    });
    if (!parsed.success) return parsed.response;

    const targetEmail = parsed.data?.email || user.email;

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
    logger.error(
      { err: error, route: "/api/user/support-access" },
      "Error creating support token"
    );
    return NextResponse.json(
      { error: "Failed to create support access token" },
      { status: 500 }
    );
  }
});

export const DELETE = withAuth(async (_request, _context, user) => {
  try {
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
    logger.error(
      { err: error, route: "/api/user/support-access" },
      "Error revoking support token"
    );
    return NextResponse.json(
      { error: "Failed to revoke support access" },
      { status: 500 }
    );
  }
});
