import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getAuthenticatedUser } from "@/lib/server-auth";

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

export async function POST(request: NextRequest) {
  try {
    const user = await getAuthenticatedUser(request);

    if (!user) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const body = await request.json();
    const { status } = body;

    let flag: string | null = null;
    let sqlInjectionDetected = false;

    if (status && typeof status === "string") {
      sqlInjectionDetected = isSQLInjectionAttempt(status);
      const upperStatus = status.toUpperCase();
      const normalizedStatus = upperStatus.replace(/\s+/g, " ");
      const isAccessingFlagsTable =
        normalizedStatus.includes("FROM FLAGS") ||
        normalizedStatus.includes("FROM`FLAGS`") ||
        normalizedStatus.includes('FROM"FLAGS"') ||
        normalizedStatus.includes("JOIN FLAGS") ||
        normalizedStatus.includes("JOIN`FLAGS`") ||
        normalizedStatus.includes('JOIN"FLAGS"') ||
        normalizedStatus.includes("FLAGS WHERE") ||
        normalizedStatus.includes("FLAGS.") ||
        /FLAGS\s*[,\s]/.test(normalizedStatus);

      if (isAccessingFlagsTable) {
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

    const statusFilter =
      status && typeof status === "string" ? `AND o.status = '${status}'` : "";

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
      const queryResults = (await prisma.$queryRawUnsafe(query)) as Record<
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
      throw error;
    }

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
    console.error("Error searching orders:", error);
    return NextResponse.json(
      { error: "Failed to search orders" },
      { status: 500 }
    );
  }
}
