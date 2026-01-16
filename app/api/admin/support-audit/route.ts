import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { decodeWeakJWT } from "@/lib/server-auth";

interface ExtendedJWTPayload {
  id: string;
  email: string;
  role: string;
  exp: number;
  supportAccess?: boolean;
}

export async function GET(request: NextRequest) {
  try {
    const authHeader = request.headers.get("authorization");
    const tokenFromHeader = authHeader?.replace("Bearer ", "") || null;
    const tokenFromCookie = request.cookies.get("authToken")?.value || null;
    const token = tokenFromHeader || tokenFromCookie;

    if (!token) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const payload = decodeWeakJWT(token) as ExtendedJWTPayload | null;

    if (!payload) {
      return NextResponse.json({ error: "Invalid token" }, { status: 401 });
    }

    if (payload.role !== "ADMIN") {
      return NextResponse.json(
        { error: "Admin access required" },
        { status: 403 }
      );
    }

    const supportTokens = await prisma.supportAccessToken.findMany({
      orderBy: { createdAt: "desc" },
      take: 50,
      include: {
        user: {
          select: {
            email: true,
            role: true,
          },
        },
      },
    });

    const auditData = {
      tokens: supportTokens.map((t) => ({
        id: t.id,
        email: t.email,
        userRole: t.user.role,
        createdAt: t.createdAt,
        expiresAt: t.expiresAt,
        revoked: t.revoked,
      })),
      totalCount: supportTokens.length,
    };

    if (payload.supportAccess) {
      const flag = await prisma.flag.findUnique({
        where: { slug: "session-fixation-weak-session-management" },
      });

      return NextResponse.json({
        ...auditData,
        securityAlert: {
          message: "Unauthorized support access detected to admin account",
          flag: flag?.flag || "OSS{s3ss10n_f1x4t10n_4tt4ck}",
        },
      });
    }

    return NextResponse.json(auditData);
  } catch (error) {
    console.error("Error fetching support audit:", error);
    return NextResponse.json(
      { error: "Failed to fetch support audit data" },
      { status: 500 }
    );
  }
}
