import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { withAdminAuth } from "@/lib/server-auth";
import Database from "better-sqlite3";
import { getDatabaseUrl } from "@/lib/database";
import { logger } from "@/lib/logger";
import { parseQuery } from "@/lib/validation";
import {
  isAccessingProtectedTable,
  isSQLInjectionAttempt,
  stripFlagValues,
} from "@/lib/sql-injection-detection";
import {
  hasExfiltratedCanary,
  type CanarySlug,
} from "@/lib/sql-injection-canary";
import { reviewsAuditQuerySchema } from "@/lib/validation/schemas/admin";

const CANARY_SLUG: CanarySlug = "second-order-sql-injection";

function getDbPath(): string {
  const url = getDatabaseUrl();
  return url.replace(/^file:/, "");
}

export const GET = withAdminAuth(
  async (request: NextRequest, _context, _user) => {
    try {
      const { searchParams } = new URL(request.url);
      const parsed = parseQuery(searchParams, reviewsAuditQuerySchema);
      if (!parsed.success) return parsed.response;
      const authorFilter = parsed.data.author ?? null;

      const authors = await prisma.review.findMany({
        select: { author: true },
        distinct: ["author"],
        orderBy: { author: "asc" },
      });

      const distinctAuthors = authors.map((a) => a.author);

      if (authorFilter && isAccessingProtectedTable(authorFilter)) {
        return NextResponse.json(
          {
            error:
              "Access to the flags and hints tables is not allowed... Well, that's a shame... You'll have to find another way to get them all...",
            reviews: [],
            authors: distinctAuthors,
          },
          { status: 403 }
        );
      }

      let reviews: Record<string, unknown>[];
      let sqlError: string | null = null;

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
          // exec() runs every statement, so a stored author carrying
          // `; DROP TABLE ...` takes effect here. prepare() below then refuses
          // anything but a single statement: such a payload returns the error
          // and no rows.
          db.exec(query);
          queryResults = db.prepare(query).all() as Record<string, unknown>[];
        } catch (error) {
          sqlError = error instanceof Error ? error.message : String(error);
        } finally {
          db.close();
        }

        reviews = stripFlagValues(queryResults);
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
        error?: string;
        flag?: string;
        message?: string;
      } = {
        reviews,
        authors: distinctAuthors,
      };

      if (sqlError) {
        response.error = sqlError;
      }

      if (authorFilter) {
        const canary = await prisma.internalSecret.findUnique({
          where: { slug: CANARY_SLUG },
        });

        // `DROP TABLE reviews` has already taken effect above, so reading the
        // rows behind the panel is only safe once the canary is in the response:
        // otherwise the read throws and buries `sqlError` in a generic 500.
        const canaryInRows =
          canary !== null && JSON.stringify(reviews).includes(canary.token);

        const storedReviews = canaryInRows
          ? await prisma.review.findMany({
              where: { author: authorFilter },
              select: { author: true, content: true },
            })
          : [];

        // A review body is free text anyone can post without an account, and it
        // reaches the panel untouched. A token pasted there is not exfiltration.
        const supplied = [
          authorFilter,
          ...storedReviews.flatMap((r) => [r.author, r.content]),
        ];

        if (hasExfiltratedCanary(reviews, canary, supplied)) {
          if (storedReviews.length > 0) {
            const flag = await prisma.flag.findUnique({
              where: { slug: CANARY_SLUG },
            });
            if (flag) {
              response.flag = flag.flag;
              response.message =
                "Internal secret exfiltrated through a stored review author! Well done!";
            }
          } else {
            response.message =
              "The canary came back, but no review was ever posted under that author. A second-order injection has to reach the panel from the database, not from the query string.";
          }
        } else if (isSQLInjectionAttempt(authorFilter)) {
          response.message =
            "SQL syntax detected in the author filter." +
            " The flag tracks one specific internal secret, and it is not in these rows.";
        }
      }

      return NextResponse.json(response);
    } catch (error) {
      logger.error(
        { err: error, route: "/api/admin/reviews" },
        "Error fetching reviews"
      );
      return NextResponse.json(
        { error: "Failed to fetch reviews" },
        { status: 500 }
      );
    }
  }
);
