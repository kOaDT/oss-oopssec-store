import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getAuthenticatedUser } from "@/lib/server-auth";

export async function POST(request: NextRequest) {
  try {
    const user = await getAuthenticatedUser(request);

    if (!user) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const body = await request.json();
    const { code, cartTotal } = body;

    if (!code || typeof code !== "string") {
      return NextResponse.json(
        { error: "Coupon code is required" },
        { status: 400 }
      );
    }

    if (typeof cartTotal !== "number" || cartTotal <= 0) {
      return NextResponse.json(
        { error: "Valid cart total is required" },
        { status: 400 }
      );
    }

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
    console.error("Error applying coupon:", error);
    return NextResponse.json(
      { error: "Failed to apply coupon" },
      { status: 500 }
    );
  }
}
