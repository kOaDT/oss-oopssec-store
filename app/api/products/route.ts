import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { logger } from "@/lib/logger";

export async function GET() {
  try {
    const products = await prisma.product.findMany({});

    return NextResponse.json(products);
  } catch (error) {
    logger.error(
      { err: error, route: "/api/products" },
      "Error fetching products"
    );
    return NextResponse.json(
      { error: "Failed to fetch products" },
      { status: 500 }
    );
  }
}
