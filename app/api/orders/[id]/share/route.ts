import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { withAuth } from "@/lib/server-auth";
import { encryptShareToken } from "@/lib/share-crypto";

export const POST = withAuth(async (request: NextRequest, context, user) => {
  try {
    const { id } = await context.params;

    const order = await prisma.order.findUnique({
      where: { id, userId: user.id },
    });

    if (!order) {
      return NextResponse.json({ error: "Order not found" }, { status: 404 });
    }

    const token = encryptShareToken(`order:${id}`);

    const protocol = request.headers.get("x-forwarded-proto") || "http";
    const host = request.headers.get("host") || "localhost:3000";
    const shareUrl = `${protocol}://${host}/api/documents/share?token=${token}`;

    return NextResponse.json({ shareUrl, token });
  } catch (error) {
    console.error("Error generating share link:", error);
    return NextResponse.json(
      { error: "Failed to generate share link" },
      { status: 500 }
    );
  }
});
