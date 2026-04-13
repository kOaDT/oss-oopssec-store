import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { withAuth } from "@/lib/server-auth";
import { logger } from "@/lib/logger";

export const GET = withAuth(async (_request, _context, user) => {
  try {
    const wishlists = await prisma.wishlist.findMany({
      where: { userId: user.id },
      select: {
        id: true,
        name: true,
        isPublic: true,
        createdAt: true,
        updatedAt: true,
        items: {
          include: {
            product: true,
          },
        },
      },
      orderBy: { updatedAt: "desc" },
    });

    return NextResponse.json(wishlists);
  } catch (error) {
    logger.error(
      { error: error, route: "/api/wishlists" },
      "Error fetching wishlists"
    );
    return NextResponse.json(
      { error: "Failed to fetch wishlists" },
      { status: 500 }
    );
  }
});

export const POST = withAuth(async (request: NextRequest, _context, user) => {
  try {
    const body = await request.json();
    const { name } = body;

    if (!name || typeof name !== "string" || name.trim().length === 0) {
      return NextResponse.json(
        { error: "Wishlist name is required" },
        { status: 400 }
      );
    }

    const wishlist = await prisma.wishlist.create({
      data: {
        name: name.trim(),
        userId: user.id,
      },
      include: {
        items: {
          include: {
            product: true,
          },
        },
      },
    });

    return NextResponse.json(wishlist, { status: 201 });
  } catch (error) {
    logger.error(
      { error: error, route: "/api/wishlists" },
      "Error creating wishlist"
    );
    return NextResponse.json(
      { error: "Failed to create wishlist" },
      { status: 500 }
    );
  }
});
