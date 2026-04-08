import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { withAuth } from "@/lib/server-auth";

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
    console.error("Error fetching profile:", error);
    return NextResponse.json(
      { error: "Failed to fetch profile" },
      { status: 500 }
    );
  }
});

export const POST = withAuth(async (request: NextRequest, _context, user) => {
  try {
    let displayName: string | undefined;
    let bio: string | undefined;
    const contentType = request.headers.get("content-type") || "";

    if (contentType.includes("application/x-www-form-urlencoded")) {
      const formData = await request.text();
      const params = new URLSearchParams(formData);
      displayName = params.get("displayName") ?? undefined;
      bio = params.get("bio") ?? undefined;
    } else {
      const body = await request.json();
      displayName = body.displayName;
      bio = body.bio;
    }

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
    console.error("Error updating profile:", error);
    return NextResponse.json(
      { error: "Failed to update profile" },
      { status: 500 }
    );
  }
});
