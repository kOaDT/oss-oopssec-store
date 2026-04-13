import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { withAdminAuth } from "@/lib/server-auth";
import { logger } from "@/lib/logger";

export const GET = withAdminAuth(async (_request, _context, _user) => {
  try {
    const products = await prisma.product.findMany({
      orderBy: { name: "asc" },
    });

    return NextResponse.json(products);
  } catch (error) {
    logger.error(
      { error: error, route: "/api/admin/products" },
      "Error fetching products"
    );
    return NextResponse.json(
      { error: "Failed to fetch products" },
      { status: 500 }
    );
  }
});
