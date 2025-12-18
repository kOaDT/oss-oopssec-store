import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getAuthenticatedUser } from "@/lib/auth";

export async function POST(request: NextRequest) {
  try {
    const user = await getAuthenticatedUser(request);

    if (!user) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const body = await request.json();
    const { total } = body;

    if (!total || typeof total !== "number" || total <= 0) {
      return NextResponse.json(
        { error: "Valid total is required" },
        { status: 400 }
      );
    }

    const cart = await prisma.cart.findFirst({
      where: { userId: user.id },
      include: {
        cartItems: true,
      },
    });

    if (!cart || cart.cartItems.length === 0) {
      return NextResponse.json({ error: "Cart is empty" }, { status: 400 });
    }

    const order = await prisma.order.create({
      data: {
        userId: user.id,
        total: total,
        status: "PENDING",
      },
    });

    await prisma.cartItem.deleteMany({
      where: {
        cartId: cart.id,
      },
    });

    return NextResponse.json({
      id: order.id,
      total: order.total,
      status: order.status,
    });
  } catch (error) {
    console.error("Error creating order:", error);
    return NextResponse.json(
      { error: "Failed to create order" },
      { status: 500 }
    );
  }
}
