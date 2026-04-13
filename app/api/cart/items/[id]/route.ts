import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { withAuth } from "@/lib/server-auth";
import { logger } from "@/lib/logger";

export const DELETE = withAuth(async (_request, context, user) => {
  try {
    const { id } = await context.params;

    const cartItem = await prisma.cartItem.findUnique({
      where: { id },
      include: {
        cart: true,
      },
    });

    if (!cartItem) {
      return NextResponse.json(
        { error: "Cart item not found" },
        { status: 404 }
      );
    }

    if (cartItem.cart.userId !== user.id) {
      return NextResponse.json({ error: "Forbidden" }, { status: 403 });
    }

    await prisma.cartItem.delete({
      where: { id },
    });

    return NextResponse.json({ success: true });
  } catch (error) {
    logger.error(
      { error: error, route: "/api/cart/items/[id]" },
      "Error deleting cart item"
    );
    return NextResponse.json(
      { error: "Failed to delete cart item" },
      { status: 500 }
    );
  }
});

export const PATCH = withAuth(async (request: NextRequest, context, user) => {
  try {
    const { id } = await context.params;
    const body = await request.json();
    const { quantity } = body;

    if (!quantity || quantity < 1) {
      return NextResponse.json(
        { error: "Valid quantity is required" },
        { status: 400 }
      );
    }

    const cartItem = await prisma.cartItem.findUnique({
      where: { id },
      include: {
        cart: true,
      },
    });

    if (!cartItem) {
      return NextResponse.json(
        { error: "Cart item not found" },
        { status: 404 }
      );
    }

    if (cartItem.cart.userId !== user.id) {
      return NextResponse.json({ error: "Forbidden" }, { status: 403 });
    }

    const updatedCartItem = await prisma.cartItem.update({
      where: { id },
      data: { quantity },
    });

    return NextResponse.json({ success: true, cartItem: updatedCartItem });
  } catch (error) {
    logger.error(
      { error: error, route: "/api/cart/items/[id]" },
      "Error updating cart item"
    );
    return NextResponse.json(
      { error: "Failed to update cart item" },
      { status: 500 }
    );
  }
});
