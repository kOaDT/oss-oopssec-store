import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

const isSQLInjectionAttempt = (input: string): boolean => {
  const sqlKeywords = [
    "UNION",
    "SELECT",
    "INSERT",
    "UPDATE",
    "DELETE",
    "DROP",
    "CREATE",
    "ALTER",
    "EXEC",
    "EXECUTE",
    "SCRIPT",
    "OR 1=1",
    "OR '1'='1",
    'OR "1"="1',
    "';",
    '";',
    "--",
    "/*",
    "*/",
    "XP_",
    "sp_",
  ];
  const upperInput = input.toUpperCase();
  return sqlKeywords.some((keyword) => upperInput.includes(keyword));
};

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const query = searchParams.get("q") || "";

    if (!query.trim()) {
      return NextResponse.json({ products: [] });
    }

    let flag: string | null = null;
    let sqlInjectionDetected = false;

    if (query && typeof query === "string") {
      sqlInjectionDetected = isSQLInjectionAttempt(query);
      const upperQuery = query.toUpperCase();
      const normalizedQuery = upperQuery.replace(/\s+/g, " ");
      const isAccessingFlagsTable =
        normalizedQuery.includes("FROM FLAGS") ||
        normalizedQuery.includes("FROM`FLAGS`") ||
        normalizedQuery.includes('FROM"FLAGS"') ||
        normalizedQuery.includes("JOIN FLAGS") ||
        normalizedQuery.includes("JOIN`FLAGS`") ||
        normalizedQuery.includes('JOIN"FLAGS"') ||
        normalizedQuery.includes("FLAGS WHERE") ||
        normalizedQuery.includes("FLAGS.") ||
        /FLAGS\s*[,\s]/.test(normalizedQuery);

      if (isAccessingFlagsTable) {
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

      results = queryResults
        .map((row: Record<string, unknown>) => {
          const result: Record<string, unknown> = {};
          for (const key in row) {
            const value = row[key];
            if (
              typeof value === "string" &&
              (value.toLowerCase().includes("flags") ||
                value.toLowerCase().includes("flag"))
            ) {
              continue;
            }
            result[key] = value;
          }
          return result;
        })
        .filter((row) => Object.keys(row).length > 0);
    } catch (error) {
      console.error("Query error:", error);
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
    console.error("Error searching products:", error);
    return NextResponse.json(
      { error: "Failed to search products" },
      { status: 500 }
    );
  }
}
