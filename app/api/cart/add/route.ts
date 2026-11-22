import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { withAuth } from "@/lib/server-auth";
import { logger } from "@/lib/logger";
import { parseBody } from "@/lib/validation";
import { addCartItemBodySchema } from "@/lib/validation/schemas/cart";
import {
  MAX_CART_ITEM_QUANTITY,
  MAX_CART_ITEM_QUANTITY_MESSAGE,
} from "@/lib/cart";

export const POST = withAuth(async (request: NextRequest, _context, user) => {
  try {
    const parsed = await parseBody(request, addCartItemBodySchema);
    if (!parsed.success) return parsed.response;
    const { productId, quantity } = parsed.data;

    const product = await prisma.product.findUnique({
      where: { id: productId },
    });

    if (!product) {
      return NextResponse.json({ error: "Product not found" }, { status: 404 });
    }

    let cart = await prisma.cart.findFirst({
      where: { userId: user.id },
      include: { cartItems: true },
    });

    if (!cart) {
      cart = await prisma.cart.create({
        data: {
          userId: user.id,
        },
        include: { cartItems: true },
      });
    }

    const existingCartItem = cart.cartItems.find(
      (item) => item.productId === productId
    );

    if (existingCartItem) {
      // One conditional UPDATE: concurrent adds can neither lose an increment nor cross the limit.
      const { count } = await prisma.cartItem.updateMany({
        where: {
          id: existingCartItem.id,
          quantity: { lte: MAX_CART_ITEM_QUANTITY - quantity },
        },
        data: { quantity: { increment: quantity } },
      });

      if (count === 0) {
        return NextResponse.json(
          { error: MAX_CART_ITEM_QUANTITY_MESSAGE },
          { status: 400 }
        );
      }
    } else {
      await prisma.cartItem.create({
        data: {
          cartId: cart.id,
          productId: productId,
          quantity: quantity,
        },
      });
    }

    return NextResponse.json({ success: true });
  } catch (error) {
    logger.error(
      { err: error, route: "/api/cart/add" },
      "Error adding to cart"
    );
    return NextResponse.json(
      { error: "Failed to add item to cart" },
      { status: 500 }
    );
  }
});
