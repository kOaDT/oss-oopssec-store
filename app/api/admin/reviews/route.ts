import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getAuthenticatedUser } from "@/lib/server-auth";
import Database from "better-sqlite3";
import { getDatabaseUrl } from "@/lib/database";

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

function getDbPath(): string {
  const url = getDatabaseUrl();
  return url.replace(/^file:/, "");
}

export async function GET(request: NextRequest) {
  const user = await getAuthenticatedUser(request);

  if (!user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  if (user.role !== "ADMIN") {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  try {
    const { searchParams } = new URL(request.url);
    const authorFilter = searchParams.get("author");

    const authors = await prisma.review.findMany({
      select: { author: true },
      distinct: ["author"],
      orderBy: { author: "asc" },
    });

    const distinctAuthors = authors.map((a) => a.author);

    let flag: string | null = null;
    let sqlInjectionDetected = false;

    if (authorFilter) {
      sqlInjectionDetected = isSQLInjectionAttempt(authorFilter);

      const upperFilter = authorFilter.toUpperCase();
      const normalizedFilter = upperFilter.replace(/\s+/g, " ");
      const isAccessingFlagsTable =
        normalizedFilter.includes("FROM FLAGS") ||
        normalizedFilter.includes("FROM`FLAGS`") ||
        normalizedFilter.includes('FROM"FLAGS"') ||
        normalizedFilter.includes("JOIN FLAGS") ||
        normalizedFilter.includes("JOIN`FLAGS`") ||
        normalizedFilter.includes('JOIN"FLAGS"') ||
        normalizedFilter.includes("FLAGS WHERE") ||
        normalizedFilter.includes("FLAGS.") ||
        /FLAGS\s*[,\s]/.test(normalizedFilter);

      if (isAccessingFlagsTable) {
        return NextResponse.json(
          {
            error:
              "Access to flags table is not allowed... Well, that's a shame... You'll have to find another way to get them all...",
            reviews: [],
            authors: distinctAuthors,
          },
          { status: 403 }
        );
      }

      if (sqlInjectionDetected) {
        const sqlInjectionFlag = await prisma.flag.findUnique({
          where: { slug: "second-order-sql-injection" },
        });
        if (sqlInjectionFlag) {
          flag = sqlInjectionFlag.flag;
        }
      }
    }

    let reviews: Record<string, unknown>[];

    if (authorFilter) {
      const query = `
        SELECT
          r.id,
          r."productId",
          r.content,
          r.author,
          r."createdAt",
          p.name as "productName"
        FROM reviews r
        INNER JOIN products p ON r."productId" = p.id
        WHERE r.author = '${authorFilter}'
        ORDER BY r."createdAt" DESC
      `;

      let queryResults: Record<string, unknown>[] = [];
      const db = new Database(getDbPath());
      try {
        db.exec(query);
        try {
          queryResults = db
            .prepare(
              `SELECT
                r.id,
                r."productId",
                r.content,
                r.author,
                r."createdAt",
                p.name as "productName"
              FROM reviews r
              INNER JOIN products p ON r."productId" = p.id
              WHERE r.author = '${authorFilter}'
              ORDER BY r."createdAt" DESC`
            )
            .all() as Record<string, unknown>[];
        } catch {
          queryResults = [];
        }
      } catch {
        queryResults = [];
      } finally {
        db.close();
      }

      reviews = queryResults
        .map((row: Record<string, unknown>) => {
          const result: Record<string, unknown> = {};
          for (const key in row) {
            const value = row[key];
            if (
              typeof value === "string" &&
              (value.toLowerCase().includes("flags") ||
                value.toLowerCase().includes("oss{"))
            ) {
              continue;
            }
            result[key] = value;
          }
          return result;
        })
        .filter((row) => Object.keys(row).length > 0);
    } else {
      const safeReviews = await prisma.review.findMany({
        include: {
          product: {
            select: { name: true },
          },
        },
        orderBy: { createdAt: "desc" },
      });

      reviews = safeReviews.map((r) => ({
        id: r.id,
        productId: r.productId,
        content: r.content,
        author: r.author,
        createdAt: r.createdAt,
        productName: r.product.name,
      }));
    }

    const response: {
      reviews: Record<string, unknown>[];
      authors: string[];
      flag?: string;
      message?: string;
    } = {
      reviews,
      authors: distinctAuthors,
    };

    if (sqlInjectionDetected && flag) {
      response.flag = flag;
      response.message = "SQL injection detected in stored review author";
    }

    return NextResponse.json(response);
  } catch (error) {
    console.error("Error fetching reviews:", error);
    return NextResponse.json(
      { error: "Failed to fetch reviews" },
      { status: 500 }
    );
  }
}
