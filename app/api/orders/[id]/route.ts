import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { withAuth, type JWTPayload } from "@/lib/server-auth";
import { logger } from "@/lib/logger";

export const GET = withAuth(async (_request, context, user) => {
  try {
    const { id } = await context.params;

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
    logger.error(
      { error: error, route: "/api/orders/[id]" },
      "Error fetching order"
    );
    return NextResponse.json(
      { error: "Failed to fetch order" },
      { status: 500 }
    );
  }
});

const updateOrderStatus = async (
  request: NextRequest,
  orderId: string,
  user: JWTPayload
): Promise<NextResponse> => {
  try {
    if (user.role !== "ADMIN") {
      return NextResponse.json({ error: "Forbidden" }, { status: 403 });
    }

    let status: string;

    const contentType = request.headers.get("content-type");
    if (contentType?.includes("application/x-www-form-urlencoded")) {
      const formData = await request.formData();
      status = formData.get("status") as string;
    } else {
      const body = await request.json();
      status = body.status;
    }

    const validStatuses: Array<
      "PENDING" | "PROCESSING" | "SHIPPED" | "DELIVERED" | "CANCELLED"
    > = ["PENDING", "PROCESSING", "SHIPPED", "DELIVERED", "CANCELLED"];
    if (
      !status ||
      !validStatuses.includes(
        status as
          | "PENDING"
          | "PROCESSING"
          | "SHIPPED"
          | "DELIVERED"
          | "CANCELLED"
      )
    ) {
      return NextResponse.json(
        {
          error: "Invalid status. Must be one of: " + validStatuses.join(", "),
        },
        { status: 400 }
      );
    }

    const order = await prisma.order.findUnique({
      where: { id: orderId },
    });

    if (!order) {
      return NextResponse.json({ error: "Order not found" }, { status: 404 });
    }

    const updatedOrder = await prisma.order.update({
      where: { id: orderId },
      data: {
        status: status as
          | "PENDING"
          | "PROCESSING"
          | "SHIPPED"
          | "DELIVERED"
          | "CANCELLED",
      },
    });

    const referer = request.headers.get("referer");

    const isFromAdminDashboard = referer?.includes("/admin") ?? false;

    const response: {
      success: boolean;
      order: {
        id: string;
        status: string;
      };
      flag?: string;
    } = {
      success: true,
      order: {
        id: updatedOrder.id,
        status: updatedOrder.status,
      },
    };

    if (!isFromAdminDashboard) {
      const csrfFlag = await prisma.flag.findUnique({
        where: { slug: "cross-site-request-forgery" },
      });
      if (csrfFlag) {
        response.flag = csrfFlag.flag;
      }
    }

    return NextResponse.json(response);
  } catch (error) {
    logger.error(
      { error: error, route: "/api/orders/[id]" },
      "Error updating order"
    );
    return NextResponse.json(
      { error: "Failed to update order" },
      { status: 500 }
    );
  }
};

export const PATCH = withAuth(async (request: NextRequest, context, user) => {
  const { id } = await context.params;
  return updateOrderStatus(request, id, user);
});

export const POST = withAuth(async (request: NextRequest, context, user) => {
  const { id } = await context.params;
  return updateOrderStatus(request, id, user);
});
