import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { withAuth } from "@/lib/server-auth";
import { logger } from "@/lib/logger";

export const GET = withAuth(async (_request, context, user) => {
  try {
    const { id } = await context.params;

    const wishlist = await prisma.wishlist.findUnique({
      where: { id },
      include: {
        items: {
          include: {
            product: true,
          },
        },
        user: {
          select: {
            email: true,
          },
        },
      },
    });

    if (!wishlist) {
      return NextResponse.json(
        { error: "Wishlist not found" },
        { status: 404 }
      );
    }

    const response: {
      id: string;
      name: string;
      ownerEmail: string;
      isPublic: boolean;
      createdAt: Date;
      updatedAt: Date;
      items: Array<{
        id: string;
        addedAt: Date;
        product: {
          id: string;
          name: string;
          price: number;
          imageUrl: string;
          description: string | null;
        };
      }>;
      flag?: string;
    } = {
      id: wishlist.id,
      name: wishlist.name,
      ownerEmail: wishlist.user.email,
      isPublic: wishlist.isPublic,
      createdAt: wishlist.createdAt,
      updatedAt: wishlist.updatedAt,
      items: wishlist.items.map((item) => ({
        id: item.id,
        addedAt: item.addedAt,
        product: {
          id: item.product.id,
          name: item.product.name,
          price: item.product.price,
          imageUrl: item.product.imageUrl,
          description: item.product.description,
        },
      })),
    };

    if (wishlist.userId !== user.id && user.role !== "ADMIN") {
      const flag = await prisma.flag.findUnique({
        where: { slug: "broken-object-level-authorization" },
      });
      if (flag) {
        response.flag = flag.flag;
      }
    }

    return NextResponse.json(response);
  } catch (error) {
    logger.error(
      { error: error, route: "/api/wishlists/[id]" },
      "Error fetching wishlist"
    );
    return NextResponse.json(
      { error: "Failed to fetch wishlist" },
      { status: 500 }
    );
  }
});

export const DELETE = withAuth(async (_request, context, user) => {
  try {
    const { id } = await context.params;

    const wishlist = await prisma.wishlist.findUnique({
      where: { id },
    });

    if (!wishlist) {
      return NextResponse.json(
        { error: "Wishlist not found" },
        { status: 404 }
      );
    }

    if (wishlist.userId !== user.id) {
      return NextResponse.json({ error: "Forbidden" }, { status: 403 });
    }

    await prisma.wishlist.delete({
      where: { id },
    });

    return NextResponse.json({ success: true });
  } catch (error) {
    logger.error(
      { error: error, route: "/api/wishlists/[id]" },
      "Error deleting wishlist"
    );
    return NextResponse.json(
      { error: "Failed to delete wishlist" },
      { status: 500 }
    );
  }
});
