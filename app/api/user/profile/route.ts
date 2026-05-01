import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { withAuth } from "@/lib/server-auth";
import { logger } from "@/lib/logger";
import { parseBody, parseFormData } from "@/lib/validation";
import { updateProfileBodySchema } from "@/lib/validation/schemas/user";

export const GET = withAuth(async (_request, _context, user) => {
  try {
    const dbUser = await prisma.user.findUnique({
      where: { id: user.id },
      select: {
        id: true,
        email: true,
        displayName: true,
        bio: true,
        role: true,
        csrfExploited: true,
      },
    });

    if (!dbUser) {
      return NextResponse.json({ error: "User not found" }, { status: 404 });
    }

    const response: Record<string, unknown> = {
      id: dbUser.id,
      email: dbUser.email,
      displayName: dbUser.displayName,
      bio: dbUser.bio,
      role: dbUser.role,
    };

    if (dbUser.csrfExploited) {
      const csrfFlag = await prisma.flag.findUnique({
        where: { slug: "csrf-profile-takeover-chain" },
      });
      if (csrfFlag) {
        response.csrfFlag = csrfFlag.flag;
      }
      await prisma.user.update({
        where: { id: user.id },
        data: { csrfExploited: false },
      });
    }

    return NextResponse.json(response);
  } catch (error) {
    logger.error(
      { err: error, route: "/api/user/profile" },
      "Error fetching profile"
    );
    return NextResponse.json(
      { error: "Failed to fetch profile" },
      { status: 500 }
    );
  }
});

export const POST = withAuth(async (request: NextRequest, _context, user) => {
  try {
    const contentType = request.headers.get("content-type") || "";
    const parsed = contentType.includes("application/x-www-form-urlencoded")
      ? await parseFormData(request, updateProfileBodySchema)
      : await parseBody(request, updateProfileBodySchema);
    if (!parsed.success) return parsed.response;
    const { displayName, bio } = parsed.data;

    const updatedUser = await prisma.user.update({
      where: { id: user.id },
      data: {
        ...(displayName !== undefined && { displayName }),
        ...(bio !== undefined && { bio }),
      },
      select: {
        id: true,
        email: true,
        displayName: true,
        bio: true,
      },
    });

    const response: Record<string, unknown> = {
      message: "Profile updated successfully",
      user: updatedUser,
    };

    const htmlTagPattern = /<[a-z][\s\S]*>/i;
    if (bio && htmlTagPattern.test(bio)) {
      const xssFlag = await prisma.flag.findUnique({
        where: { slug: "self-xss-profile-injection" },
      });
      if (xssFlag) {
        response.flag = xssFlag.flag;
      }
    }

    const referer = request.headers.get("referer");
    const isFromProfilePage = referer?.includes("/profile") ?? false;

    if (!isFromProfilePage) {
      await prisma.user.update({
        where: { id: user.id },
        data: { csrfExploited: true },
      });
    }

    return NextResponse.json(response);
  } catch (error) {
    logger.error(
      { err: error, route: "/api/user/profile" },
      "Error updating profile"
    );
    return NextResponse.json(
      { error: "Failed to update profile" },
      { status: 500 }
    );
  }
});
