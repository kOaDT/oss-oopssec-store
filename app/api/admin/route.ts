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
    const token = authHeader?.replace("Bearer ", "") || null;

    if (!token) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const user = decodeWeakJWT(token) as ExtendedJWTPayload | null;

    if (!user) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    if (user.role !== "ADMIN") {
      return NextResponse.json({ error: "Forbidden" }, { status: 403 });
    }

    const dbUser = await prisma.user.findUnique({
      where: { id: user.id },
      select: { id: true, email: true, role: true },
    });

    if (!dbUser) {
      return NextResponse.json({ error: "User not found" }, { status: 404 });
    }

    if (dbUser.role !== "ADMIN") {
      const flag = await prisma.flag.findUnique({
        where: { slug: "weak-jwt-secret" },
      });

      if (flag) {
        return NextResponse.json({
          message: "Flag retrieved successfully",
          flag: flag.flag,
        });
      }
    }

    if (user.supportAccess && dbUser.role === "ADMIN") {
      const sessionFixationFlag = await prisma.flag.findUnique({
        where: { slug: "session-fixation-weak-session-management" },
      });

      if (sessionFixationFlag) {
        return NextResponse.json({
          message: "Unauthorized support access detected to admin account",
          flag: sessionFixationFlag.flag,
          user: {
            id: dbUser.id,
            email: dbUser.email,
            role: dbUser.role,
          },
        });
      }
    }

    const expectedEmails = [
      "alice@example.com",
      "bob@example.com",
      "admin@oss.com",
    ];

    if (dbUser.role === "ADMIN" && !expectedEmails.includes(dbUser.email)) {
      const massAssignmentFlag = await prisma.flag.findUnique({
        where: { slug: "mass-assignment" },
      });

      if (massAssignmentFlag) {
        return NextResponse.json({
          message: "Welcome, administrator",
          flag: massAssignmentFlag.flag,
          user: {
            id: dbUser.id,
            email: dbUser.email,
            role: dbUser.role,
          },
        });
      }
    }

    const md5Flag = await prisma.flag.findUnique({
      where: { slug: "weak-md5-hashing" },
    });

    if (md5Flag) {
      return NextResponse.json({
        message: "Welcome, administrator",
        flag: md5Flag.flag,
        user: {
          id: dbUser.id,
          email: dbUser.email,
          role: dbUser.role,
        },
      });
    }

    return NextResponse.json({
      message: "Welcome, administrator",
      user: {
        id: dbUser.id,
        email: dbUser.email,
        role: dbUser.role,
      },
    });
  } catch (error) {
    console.error("Error in admin endpoint:", error);
    return NextResponse.json(
      { error: "Failed to process request" },
      { status: 500 }
    );
  }
}
