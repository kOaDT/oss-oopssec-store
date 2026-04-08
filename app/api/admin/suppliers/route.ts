import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { withAdminAuth } from "@/lib/server-auth";

export const GET = withAdminAuth(async (_request, _context, _user) => {
  const orders = await prisma.supplierOrder.findMany({
    orderBy: { createdAt: "desc" },
  });

  return NextResponse.json(orders);
});
