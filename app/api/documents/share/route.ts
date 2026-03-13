import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { decryptShareToken } from "@/lib/share-crypto";

export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url);
  const token = searchParams.get("token");

  if (!token || !/^[0-9a-f]+$/i.test(token) || token.length < 64) {
    return NextResponse.json({ error: "Missing share token" }, { status: 400 });
  }

  let resourcePath: string;
  try {
    resourcePath = decryptShareToken(token);
  } catch {
    return NextResponse.json(
      { error: "Invalid share token format" },
      { status: 400 }
    );
  }

  const colonIndex = resourcePath.indexOf(":");
  if (colonIndex === -1) {
    return NextResponse.json(
      { error: "Shared resource not found" },
      { status: 404 }
    );
  }

  const resourceType = resourcePath.substring(0, colonIndex);
  const resourceId = resourcePath.substring(colonIndex + 1);

  const supportedTypes = ["order", "report"];
  if (!supportedTypes.includes(resourceType)) {
    return NextResponse.json(
      {
        error: `Unsupported resource type '${resourceType}'. Expected: ${supportedTypes.join(", ")}`,
      },
      { status: 400 }
    );
  }

  if (resourceType === "order") {
    const order = await prisma.order.findUnique({
      where: { id: resourceId },
      include: {
        user: true,
        items: {
          include: { product: true },
        },
        address: true,
      },
    });

    if (!order) {
      return NextResponse.json(
        { error: "Shared resource not found" },
        { status: 404 }
      );
    }

    const emailName = order.user.email.split("@")[0];
    const customerName = emailName.charAt(0).toUpperCase() + emailName.slice(1);

    return NextResponse.json({
      type: "order",
      order: {
        id: order.id,
        total: order.total,
        status: order.status,
        customerName,
        createdAt: order.createdAt,
        items: order.items.map((item) => ({
          name: item.product.name,
          quantity: item.quantity,
          price: item.priceAtPurchase,
        })),
        deliveryAddress: {
          street: order.address.street,
          city: order.address.city,
          state: order.address.state,
          zipCode: order.address.zipCode,
          country: order.address.country,
        },
      },
    });
  }

  if (resourceType === "report") {
    if (resourceId === "internal") {
      const flag = await prisma.flag.findUnique({
        where: { slug: "aes-cbc-padding-oracle" },
      });

      return NextResponse.json({
        type: "report",
        title: "Internal Security Audit Report",
        content:
          "Quarterly security assessment completed. All systems operational. No critical findings.",
        flag: flag?.flag,
      });
    }
  }

  return NextResponse.json(
    { error: "Shared resource not found" },
    { status: 404 }
  );
}
