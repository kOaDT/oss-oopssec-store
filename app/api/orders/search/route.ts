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
import { orderSearchBodySchema } from "@/lib/validation/schemas/orders";

export const POST = withAuth(async (request: NextRequest, _context, user) => {
  try {
    const parsed = await parseBody(request, orderSearchBodySchema);
    if (!parsed.success) return parsed.response;
    const { status } = parsed.data;

    let flag: string | null = null;
    let sqlInjectionDetected = false;

    if (status) {
      sqlInjectionDetected = isSQLInjectionAttempt(status);

      if (isAccessingFlagsTable(status)) {
        return NextResponse.json(
          {
            error:
              "Access to flags table is not allowed... Well, that's a shame... You'll have to find another way to get them all...",
            orders: [],
          },
          { status: 403 }
        );
      }

      if (sqlInjectionDetected) {
        const sqlInjectionFlag = await prisma.flag.findUnique({
          where: { slug: "sql-injection" },
        });
        if (sqlInjectionFlag) {
          flag = sqlInjectionFlag.flag;
        }
      }
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

    const results = stripFlagValues(
      (await prisma.$queryRawUnsafe(query)) as Record<string, unknown>[]
    );

    const response: {
      orders: Record<string, unknown>[];
      flag?: string;
      message?: string;
    } = {
      orders: results,
    };

    if (sqlInjectionDetected && flag && results.length > 0) {
      response.flag = flag;
      response.message = "SQL injection detected";
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
