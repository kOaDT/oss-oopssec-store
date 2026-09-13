import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { logger } from "@/lib/logger";
import { parseQuery } from "@/lib/validation";
import {
  isAccessingFlagsTable,
  isSQLInjectionAttempt,
  stripFlagValues,
} from "@/lib/sql-injection-detection";
import { hasExfiltratedCanary } from "@/lib/sql-injection-canary";
import { productSearchQuerySchema } from "@/lib/validation/schemas/products";

const CANARY_SLUG = "product-search-sql-injection";

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const parsed = parseQuery(searchParams, productSearchQuerySchema);
    if (!parsed.success) return parsed.response;
    const query = parsed.data.q ?? "";

    if (!query.trim()) {
      return NextResponse.json({ products: [] });
    }

    if (isAccessingFlagsTable(query)) {
      return NextResponse.json(
        {
          error:
            "Access to flags table is not allowed... Well, that's a shame... You'll have to find another way to get them all...",
          products: [],
        },
        { status: 403 }
      );
    }

    const sqlQuery = `
      SELECT
        id,
        name,
        description,
        price,
        "imageUrl"
      FROM products
      WHERE name LIKE '%${query}%' OR description LIKE '%${query}%'
      ORDER BY name ASC
      LIMIT 50
    `;

    let results: Record<string, unknown>[] = [];
    try {
      const queryResults = (await prisma.$queryRawUnsafe(sqlQuery)) as Record<
        string,
        unknown
      >[];

      results = stripFlagValues(queryResults);
    } catch (error) {
      logger.error(
        { err: error, route: "/api/products/search" },
        "Query error"
      );
      return NextResponse.json(
        {
          error: error instanceof Error ? error.message : "Search failed",
          products: [],
        },
        { status: 500 }
      );
    }

    const canary = await prisma.internalSecret.findUnique({
      where: { slug: CANARY_SLUG },
    });

    const response: {
      products: Record<string, unknown>[];
      flag?: string;
      message?: string;
    } = {
      products: results,
    };

    if (hasExfiltratedCanary(results, canary)) {
      const flag = await prisma.flag.findUnique({
        where: { slug: CANARY_SLUG },
      });
      if (flag) {
        response.flag = flag.flag;
        response.message =
          "Internal secret exfiltrated through the product search! Well done!";
      }
    } else if (isSQLInjectionAttempt(query)) {
      response.message =
        "SQL syntax detected in the search term, but the results hold nothing you did not already know.";
    }

    return NextResponse.json(response);
  } catch (error) {
    logger.error(
      { err: error, route: "/api/products/search" },
      "Error searching products"
    );
    return NextResponse.json(
      { error: "Failed to search products" },
      { status: 500 }
    );
  }
}
