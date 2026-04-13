import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { withAuth, withAdminAuth } from "@/lib/server-auth";
import { generateInvoice } from "@/lib/invoice";
import { logger } from "@/lib/logger";

export const GET = withAdminAuth(async (_request, _context, _user) => {
  try {
    const orders = await prisma.order.findMany({
      include: {
        user: {
          select: {
            email: true,
          },
        },
        address: true,
      },
      orderBy: {
        id: "desc",
      },
    });

    return NextResponse.json(orders);
  } catch (error) {
    logger.error(
      { error: error, route: "/api/orders" },
      "Error fetching orders"
    );
    return NextResponse.json(
      { error: "Failed to fetch orders" },
      { status: 500 }
    );
  }
});

export const POST = withAuth(async (request: NextRequest, _context, user) => {
  try {
    const body = await request.json();
    const { total, couponCode } = body;

    if (!total || typeof total !== "number" || total <= 0) {
      return NextResponse.json(
        { error: "Valid total is required" },
        { status: 400 }
      );
    }

    const cart = await prisma.cart.findFirst({
      where: { userId: user.id },
      include: {
        cartItems: {
          include: {
            product: true,
          },
        },
      },
    });

    if (!cart || cart.cartItems.length === 0) {
      return NextResponse.json({ error: "Cart is empty" }, { status: 400 });
    }

    const calculatedTotal = cart.cartItems.reduce(
      (sum, item) => sum + item.product.price * item.quantity,
      0
    );

    let expectedTotal = calculatedTotal;
    let couponRaceFlag: string | undefined;

    if (couponCode && typeof couponCode === "string") {
      const coupon = await prisma.coupon.findUnique({
        where: { code: couponCode.toUpperCase() },
      });

      if (
        coupon &&
        (!coupon.expiresAt || coupon.expiresAt >= new Date()) &&
        coupon.usedCount < coupon.maxUses
      ) {
        // Simulate discount validation processing — this gap is the race window
        await new Promise((resolve) => setTimeout(resolve, 150));

        const updated = await prisma.coupon.update({
          where: { code: coupon.code },
          data: { usedCount: { increment: 1 } },
        });

        expectedTotal = calculatedTotal * (1 - coupon.discount);

        if (updated.usedCount > coupon.maxUses) {
          couponRaceFlag = "OSS{r4c3_c0nd1t10n_c0up0n_4bus3}";
        }
      }
    }

    const userWithAddress = await prisma.user.findUnique({
      where: { id: user.id },
      include: { address: true },
    });

    if (!userWithAddress?.addressId) {
      return NextResponse.json(
        { error: "User address not found" },
        { status: 400 }
      );
    }

    let order: {
      id: string;
      total: number;
      status: string;
      createdAt: Date;
    } | null = null;
    // The race condition challenge fires ~30 concurrent requests here. All compute
    // the same next ID, race to insert it, and the losers hit a unique-constraint
    // violation. This retry loop re-scans to find the true numeric max on each
    // collision so every request eventually succeeds and reaches the flag check.
    let attempts = 0;
    while (!order && attempts < 20) {
      attempts++;
      const allOrders = await prisma.order.findMany({
        select: { id: true },
      });
      const maxNum = allOrders.reduce((max, o) => {
        if (!o.id.startsWith("ORD-")) return max;
        const n = parseInt(o.id.replace("ORD-", ""), 10);
        return isNaN(n) ? max : Math.max(max, n);
      }, 0);
      const nextId = `ORD-${(maxNum + 1).toString().padStart(3, "0")}`;
      try {
        order = await prisma.order.create({
          data: {
            id: nextId,
            userId: user.id,
            addressId: userWithAddress.addressId,
            total: total,
            status: "PENDING",
          },
        });
      } catch {
        // Concurrent request claimed this ID — retry with a fresh read
      }
    }

    if (!order) {
      return NextResponse.json(
        { error: "Failed to create order" },
        { status: 500 }
      );
    }

    const orderItems = await Promise.all(
      cart.cartItems.map((item) =>
        prisma.orderItem.create({
          data: {
            orderId: order.id,
            productId: item.productId,
            quantity: item.quantity,
            priceAtPurchase: item.product.price,
          },
          include: {
            product: true,
          },
        })
      )
    );

    const emailName = user.email.split("@")[0];
    const customerName = emailName.charAt(0).toUpperCase() + emailName.slice(1);

    try {
      await generateInvoice({
        orderId: order.id,
        createdAt: order.createdAt,
        customerName,
        customerEmail: user.email,
        address: userWithAddress.address!,
        items: orderItems.map((item) => ({
          name: item.product.name,
          quantity: item.quantity,
          priceAtPurchase: item.priceAtPurchase,
        })),
        total: order.total,
      });
    } catch (invoiceError) {
      logger.error(
        { error: invoiceError, route: "/api/orders" },
        "Failed to generate invoice"
      );
    }

    await prisma.cartItem.deleteMany({
      where: {
        cartId: cart.id,
      },
    });

    const response: {
      id: string;
      total: number;
      status: string;
      flag?: string;
    } = {
      id: order.id,
      total: order.total,
      status: order.status,
    };

    if (Math.abs(total - expectedTotal) > 0.01) {
      response.flag = "OSS{cl13nt_s1d3_pr1c3_m4n1pul4t10n}";
    }

    if (couponRaceFlag) {
      response.flag = couponRaceFlag;
    }

    return NextResponse.json(response);
  } catch (error) {
    logger.error(
      { error: error, route: "/api/orders" },
      "Error creating order"
    );
    return NextResponse.json(
      { error: "Failed to create order" },
      { status: 500 }
    );
  }
});
