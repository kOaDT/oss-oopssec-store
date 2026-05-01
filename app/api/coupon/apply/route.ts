import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { withAuth } from "@/lib/server-auth";
import { logger } from "@/lib/logger";
import { parseBody } from "@/lib/validation";
import { applyCouponBodySchema } from "@/lib/validation/schemas/coupons";

export const POST = withAuth(async (request: NextRequest, _context, _user) => {
  try {
    const parsed = await parseBody(request, applyCouponBodySchema);
    if (!parsed.success) return parsed.response;
    const { code, cartTotal } = parsed.data;

    const coupon = await prisma.coupon.findUnique({
      where: { code: code.toUpperCase() },
    });

    if (!coupon) {
      return NextResponse.json({ error: "Coupon not found" }, { status: 404 });
    }

    if (coupon.expiresAt && coupon.expiresAt < new Date()) {
      return NextResponse.json(
        { error: "Coupon has expired" },
        { status: 400 }
      );
    }

    if (coupon.usedCount >= coupon.maxUses) {
      return NextResponse.json(
        { error: "Coupon has already been used" },
        { status: 400 }
      );
    }

    const discountedTotal = cartTotal * (1 - coupon.discount);

    return NextResponse.json({
      discountedTotal,
      discountPercent: coupon.discount * 100,
    });
  } catch (error) {
    logger.error(
      { err: error, route: "/api/coupon/apply" },
      "Error applying coupon"
    );
    return NextResponse.json(
      { error: "Failed to apply coupon" },
      { status: 500 }
    );
  }
});
