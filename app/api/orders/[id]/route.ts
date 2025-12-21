import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getAuthenticatedUser } from "@/lib/auth";

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const user = await getAuthenticatedUser(request);

    if (!user) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const { id } = await params;

    const order = await prisma.order.findUnique({
      where: { id },
      include: {
        user: {
          include: {
            address: true,
          },
        },
        address: true,
      },
    });

    if (!order) {
      return NextResponse.json({ error: "Order not found" }, { status: 404 });
    }

    const emailName = order.user.email.split("@")[0];
    const customerName = emailName.charAt(0).toUpperCase() + emailName.slice(1);

    const response: {
      id: string;
      total: number;
      status: string;
      customerName: string;
      customerEmail: string;
      deliveryAddress: {
        street: string;
        city: string;
        state: string;
        zipCode: string;
        country: string;
      };
      flag?: string;
    } = {
      id: order.id,
      total: order.total,
      status: order.status,
      customerName,
      customerEmail: order.user.email,
      deliveryAddress: {
        street: order.address.street,
        city: order.address.city,
        state: order.address.state,
        zipCode: order.address.zipCode,
        country: order.address.country,
      },
    };

    if (order.userId !== user.id) {
      response.flag = "OSS{1ns3cur3_d1r3ct_0bj3ct_r3f3r3nc3}";
    }

    return NextResponse.json(response);
  } catch (error) {
    console.error("Error fetching order:", error);
    return NextResponse.json(
      { error: "Failed to fetch order" },
      { status: 500 }
    );
  }
}
