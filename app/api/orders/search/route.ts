import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { withAuth } from "@/lib/server-auth";
import { logger } from "@/lib/logger";
import { parseBody } from "@/lib/validation";
import {
  isAccessingFlagsTable,
  isSQLInjectionAttempt,
  stripFlagValues,
} from "@/lib/sql-injection-detection";
import { hasExfiltratedCanary } from "@/lib/sql-injection-canary";
import { orderSearchBodySchema } from "@/lib/validation/schemas/orders";

const CANARY_SLUG = "sql-injection";

export const POST = withAuth(async (request: NextRequest, _context, user) => {
  try {
    const parsed = await parseBody(request, orderSearchBodySchema);
    if (!parsed.success) return parsed.response;
    const { status } = parsed.data;

    if (status && isAccessingFlagsTable(status)) {
      return NextResponse.json(
        {
          error:
            "Access to flags table is not allowed... Well, that's a shame... You'll have to find another way to get them all...",
          orders: [],
        },
        { status: 403 }
      );
    }

    const statusFilter = status ? `AND o.status = '${status}'` : "";

    const query = `
      SELECT
        o.id,
        o.total,
        o.status,
        o."userId",
        a.street,
        a.city,
        a.state,
        a."zipCode",
        a.country
      FROM orders o
      INNER JOIN addresses a ON o."addressId" = a.id
      WHERE o."userId" = '${user.id}' ${statusFilter}
      ORDER BY o.id DESC
    `;

    let results: Record<string, unknown>[] = [];
    try {
      results = stripFlagValues(
        (await prisma.$queryRawUnsafe(query)) as Record<string, unknown>[]
      );
    } catch (error) {
      logger.error({ err: error, route: "/api/orders/search" }, "Query error");
      return NextResponse.json(
        {
          error: error instanceof Error ? error.message : "Search failed",
          orders: [],
        },
        { status: 500 }
      );
    }

    const canary = await prisma.internalSecret.findUnique({
      where: { slug: CANARY_SLUG },
    });

    const response: {
      orders: Record<string, unknown>[];
      flag?: string;
      message?: string;
    } = {
      orders: results,
    };

    if (hasExfiltratedCanary(results, canary, [status ?? ""])) {
      const flag = await prisma.flag.findUnique({
        where: { slug: CANARY_SLUG },
      });
      if (flag) {
        response.flag = flag.flag;
        response.message =
          "Internal secret exfiltrated through the order search! Well done!";
      }
    } else if (status && isSQLInjectionAttempt(status)) {
      response.message =
        "SQL syntax detected in the status filter." +
        " The flag tracks one specific internal secret, and it is not in these rows.";
    }

    return NextResponse.json(response);
  } catch (error) {
    logger.error(
      { err: error, route: "/api/orders/search" },
      "Error searching orders"
    );
    return NextResponse.json(
      { error: "Failed to search orders" },
      { status: 500 }
    );
  }
});
