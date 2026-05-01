import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getAuthenticatedUser } from "@/lib/server-auth";
import { logger } from "@/lib/logger";
import { parseBody } from "@/lib/validation";
import { createReviewBodySchema } from "@/lib/validation/schemas/products";

export async function GET(
  request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;

    const product = await prisma.product.findUnique({
      where: { id },
    });

    if (!product) {
      return NextResponse.json({ error: "Product not found" }, { status: 404 });
    }

    const reviews = await prisma.review.findMany({
      where: { productId: id },
      orderBy: { createdAt: "desc" },
    });

    return NextResponse.json(reviews);
  } catch (error) {
    logger.error(
      { err: error, route: "/api/products/[id]/reviews" },
      "Error fetching reviews"
    );
    return NextResponse.json(
      { error: "Failed to fetch reviews" },
      { status: 500 }
    );
  }
}

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    const parsed = await parseBody(request, createReviewBodySchema);
    if (!parsed.success) return parsed.response;
    const { content, author: requestAuthor } = parsed.data;

    const product = await prisma.product.findUnique({
      where: { id },
    });

    if (!product) {
      return NextResponse.json({ error: "Product not found" }, { status: 404 });
    }

    const user = await getAuthenticatedUser(request);
    const author =
      requestAuthor && requestAuthor.trim().length > 0
        ? requestAuthor.trim()
        : user?.email || "anonymous";

    const review = await prisma.review.create({
      data: {
        productId: id,
        content: content.trim(),
        author,
      },
    });

    return NextResponse.json(review, { status: 201 });
  } catch (error) {
    logger.error(
      { err: error, route: "/api/products/[id]/reviews" },
      "Error creating review"
    );
    return NextResponse.json(
      { error: "Failed to create review" },
      { status: 500 }
    );
  }
}
