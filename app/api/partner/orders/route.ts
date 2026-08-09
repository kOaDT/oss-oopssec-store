import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { readBearerToken, verifyPartnerToken } from "@/lib/partner-auth";

export async function GET(request: NextRequest) {
  const token = readBearerToken(request);
  if (!token) {
    return NextResponse.json(
      { error: "Missing Authorization: Bearer <token> header" },
      { status: 401 }
    );
  }

  const partner = verifyPartnerToken(token);
  if (!partner) {
    return NextResponse.json(
      { error: "Invalid or expired partner token" },
      { status: 401 }
    );
  }

  const orders = await prisma.supplierOrder.findMany({
    where: { supplierId: partner.sub },
    orderBy: { createdAt: "desc" },
  });

  return NextResponse.json({
    partnerId: partner.sub,
    count: orders.length,
    orders: orders.map((order) => ({
      purchaseOrderId: order.orderId,
      total: order.total,
      notes: order.notes,
      createdAt: order.createdAt,
    })),
  });
}
