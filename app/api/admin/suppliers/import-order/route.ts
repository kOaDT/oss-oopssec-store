import { NextRequest, NextResponse } from "next/server";
import { getAuthenticatedUser } from "@/lib/server-auth";
import { prisma } from "@/lib/prisma";
import libxmljs from "libxmljs2";
import path from "path";

const SUPPLIER_REGISTRY_PATH = path.join(process.cwd(), "flag-xxe.txt");

export async function POST(request: NextRequest) {
  const user = await getAuthenticatedUser(request);

  if (!user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  if (user.role !== "ADMIN") {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  try {
    const rawXml = await request.text();

    if (!rawXml.trim()) {
      return NextResponse.json(
        { error: "Empty request body. Please provide XML data." },
        { status: 400 }
      );
    }

    const doc = libxmljs.parseXmlString(rawXml, { noent: true, dtdload: true });

    const root = doc.root();
    if (!root || root.name() !== "order") {
      return NextResponse.json(
        {
          error: "Invalid XML structure. Expected root element <order>.",
          debug: {
            config: SUPPLIER_REGISTRY_PATH,
            message: "The XML must match the supplier order schema.",
            expected: ["supplierId", "orderId", "total", "notes (optional)"],
          },
        },
        { status: 400 }
      );
    }

    const getText = (name: string) =>
      (root.get(name) as libxmljs.Element | null)?.text()?.trim() || "";

    const supplierId = getText("supplierId");
    const orderId = getText("orderId");
    const total = parseFloat(getText("total")) || 0;
    const notes = getText("notes");

    if (!supplierId || !orderId) {
      return NextResponse.json(
        {
          error: "Missing required fields: supplierId and orderId.",
          debug: {
            config: SUPPLIER_REGISTRY_PATH,
            received: {
              supplierId: supplierId || null,
              orderId: orderId || null,
            },
          },
        },
        { status: 400 }
      );
    }

    const supplierOrder = await prisma.supplierOrder.create({
      data: {
        supplierId,
        orderId,
        total,
        notes: notes || null,
      },
    });

    return NextResponse.json({
      message: "Supplier order imported successfully.",
      order: {
        id: supplierOrder.id,
        supplierId: supplierOrder.supplierId,
        orderId: supplierOrder.orderId,
        total: supplierOrder.total,
        notes: supplierOrder.notes,
        createdAt: supplierOrder.createdAt,
      },
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error";
    return NextResponse.json(
      {
        error: `Failed to parse XML: ${message}`,
      },
      { status: 400 }
    );
  }
}
