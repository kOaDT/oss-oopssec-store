import { NextRequest, NextResponse } from "next/server";
import { getAuthenticatedUser } from "@/lib/server-auth";
import { prisma } from "@/lib/prisma";
import { XMLParser } from "fast-xml-parser";
import fs from "fs";

function resolveExternalEntities(xml: string): string {
  const doctypeRegex = new RegExp(
    "<!DOCTYPE\\s+\\w+\\s*\\[([^\\]]*)\\]\\s*>",
    "is"
  );
  const doctypeMatch = xml.match(doctypeRegex);
  if (!doctypeMatch) return xml;

  const internalSubset = doctypeMatch[1];
  const entityRegex = /<!ENTITY\s+(\w+)\s+SYSTEM\s+["']([^"']+)["']\s*>/gi;

  let resolved = xml;
  let match;

  while ((match = entityRegex.exec(internalSubset)) !== null) {
    const entityName = match[1];
    const systemUri = match[2];

    let entityValue = "";

    if (systemUri.startsWith("file://")) {
      const filePath = systemUri.slice(7);
      try {
        entityValue = fs.readFileSync(filePath, "utf-8");
      } catch {
        entityValue = `[Error: cannot read ${filePath}]`;
      }
    } else if (systemUri.startsWith("/")) {
      try {
        entityValue = fs.readFileSync(systemUri, "utf-8");
      } catch {
        entityValue = `[Error: cannot read ${systemUri}]`;
      }
    }

    resolved = resolved.replaceAll(`&${entityName};`, entityValue);
  }

  resolved = resolved.replace(doctypeRegex, "");

  return resolved;
}

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

    const resolvedXml = resolveExternalEntities(rawXml);

    const parser = new XMLParser({
      ignoreAttributes: false,
      parseTagValue: true,
      trimValues: true,
    });

    const parsed = parser.parse(resolvedXml);

    if (!parsed.order) {
      return NextResponse.json(
        { error: "Invalid XML structure. Expected root element <order>." },
        { status: 400 }
      );
    }

    const order = parsed.order;

    const supplierId = String(order.supplierId || "").trim();
    const orderId = String(order.orderId || "").trim();
    const total = parseFloat(order.total) || 0;
    const notes = String(order.notes ?? "").trim();

    if (!supplierId || !orderId) {
      return NextResponse.json(
        { error: "Missing required fields: supplierId and orderId." },
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
      { error: `Failed to parse XML: ${message}` },
      { status: 400 }
    );
  }
}
