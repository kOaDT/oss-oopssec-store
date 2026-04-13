import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { withAuth } from "@/lib/server-auth";
import { logger } from "@/lib/logger";

export const GET = withAuth(async (_request, _context, user) => {
  try {
    const dbUser = await prisma.user.findUnique({
      where: { id: user.id },
      include: {
        address: true,
      },
    });

    if (!dbUser) {
      return NextResponse.json({ error: "User not found" }, { status: 404 });
    }

    return NextResponse.json({
      id: dbUser.id,
      email: dbUser.email,
      role: dbUser.role,
      displayName: dbUser.displayName,
      bio: dbUser.bio,
      address: dbUser.address
        ? {
            street: dbUser.address.street,
            city: dbUser.address.city,
            state: dbUser.address.state,
            zipCode: dbUser.address.zipCode,
            country: dbUser.address.country,
          }
        : null,
    });
  } catch (error) {
    logger.error({ error: error, route: "/api/user" }, "Error fetching user");
    return NextResponse.json(
      { error: "Failed to fetch user" },
      { status: 500 }
    );
  }
});
