import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getAuthenticatedUser } from "@/lib/server-auth";
import { generateInvoice } from "@/lib/invoice";

export async function GET(request: NextRequest) {
  try {
    const user = await getAuthenticatedUser(request);

    if (!user) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    if (user.role !== "ADMIN") {
      return NextResponse.json({ error: "Forbidden" }, { status: 403 });
    }

    const orders = await prisma.order.findMany({
      include: {
        user: {
          select: {
            email: true,
          },
        },
        address: true,
      },
      orderBy: {
        id: "desc",
      },
    });

    return NextResponse.json(orders);
  } catch (error) {
    console.error("Error fetching orders:", error);
    return NextResponse.json(
      { error: "Failed to fetch orders" },
      { status: 500 }
    );
  }
}

export async function POST(request: NextRequest) {
  try {
    const user = await getAuthenticatedUser(request);

    if (!user) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const body = await request.json();
    const { total } = body;

    if (!total || typeof total !== "number" || total <= 0) {
      return NextResponse.json(
        { error: "Valid total is required" },
        { status: 400 }
      );
    }

    const cart = await prisma.cart.findFirst({
      where: { userId: user.id },
      include: {
        cartItems: {
          include: {
            product: true,
          },
        },
      },
    });

    if (!cart || cart.cartItems.length === 0) {
      return NextResponse.json({ error: "Cart is empty" }, { status: 400 });
    }

    const calculatedTotal = cart.cartItems.reduce(
      (sum, item) => sum + item.product.price * item.quantity,
      0
    );

    const allOrders = await prisma.order.findMany({
      select: {
        id: true,
      },
    });

    const ordOrders = allOrders
      .filter((order) => order.id.startsWith("ORD-"))
      .map((order) => {
        const number = parseInt(order.id.replace("ORD-", ""), 10);
        return isNaN(number) ? 0 : number;
      });

    const maxOrderNumber = ordOrders.length > 0 ? Math.max(...ordOrders) : 0;
    const nextOrderNumber = maxOrderNumber + 1;
    const orderId = `ORD-${nextOrderNumber.toString().padStart(3, "0")}`;

    const userWithAddress = await prisma.user.findUnique({
      where: { id: user.id },
      include: { address: true },
    });

    if (!userWithAddress?.addressId) {
      return NextResponse.json(
        { error: "User address not found" },
        { status: 400 }
      );
    }

    const order = await prisma.order.create({
      data: {
        id: orderId,
        userId: user.id,
        addressId: userWithAddress.addressId,
        total: total,
        status: "PENDING",
      },
    });

    const orderItems = await Promise.all(
      cart.cartItems.map((item) =>
        prisma.orderItem.create({
          data: {
            orderId: order.id,
            productId: item.productId,
            quantity: item.quantity,
            priceAtPurchase: item.product.price,
          },
          include: {
            product: true,
          },
        })
      )
    );

    const emailName = user.email.split("@")[0];
    const customerName = emailName.charAt(0).toUpperCase() + emailName.slice(1);

    try {
      await generateInvoice({
        orderId: order.id,
        createdAt: order.createdAt,
        customerName,
        customerEmail: user.email,
        address: userWithAddress.address!,
        items: orderItems.map((item) => ({
          name: item.product.name,
          quantity: item.quantity,
          priceAtPurchase: item.priceAtPurchase,
        })),
        total: order.total,
      });
    } catch (invoiceError) {
      console.error("Failed to generate invoice:", invoiceError);
    }

    await prisma.cartItem.deleteMany({
      where: {
        cartId: cart.id,
      },
    });

    const response: {
      id: string;
      total: number;
      status: string;
      flag?: string;
    } = {
      id: order.id,
      total: order.total,
      status: order.status,
    };

    if (Math.abs(total - calculatedTotal) > 0.01) {
      response.flag = "OSS{cl13nt_s1d3_pr1c3_m4n1pul4t10n}";
    }

    return NextResponse.json(response);
  } catch (error) {
    console.error("Error creating order:", error);
    return NextResponse.json(
      { error: "Failed to create order" },
      { status: 500 }
    );
  }
}
