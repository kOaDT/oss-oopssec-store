import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { logger } from "@/lib/logger";
import { parseQuery } from "@/lib/validation";
import {
  isAccessingFlagsTable,
  isSQLInjectionAttempt,
  stripFlagValues,
} from "@/lib/sql-injection-detection";
import { productSearchQuerySchema } from "@/lib/validation/schemas/products";

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const parsed = parseQuery(searchParams, productSearchQuerySchema);
    if (!parsed.success) return parsed.response;
    const query = parsed.data.q ?? "";

    if (!query.trim()) {
      return NextResponse.json({ products: [] });
    }

    let flag: string | null = null;
    let sqlInjectionDetected = false;

    if (query && typeof query === "string") {
      sqlInjectionDetected = isSQLInjectionAttempt(query);

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

      if (sqlInjectionDetected) {
        const sqlInjectionFlag = await prisma.flag.findUnique({
          where: { slug: "product-search-sql-injection" },
        });
        if (sqlInjectionFlag) {
          flag = sqlInjectionFlag.flag;
        }
      }
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
        { error: "Search failed", products: [] },
        { status: 500 }
      );
    }

    const response: {
      products: Record<string, unknown>[];
      flag?: string;
      message?: string;
    } = {
      products: results,
    };

    if (sqlInjectionDetected && flag) {
      response.flag = flag;
      response.message = "SQL injection detected";
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
