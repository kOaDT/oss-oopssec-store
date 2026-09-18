import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { logger } from "@/lib/logger";
import { parseBody } from "@/lib/validation";
import {
  isAccessingProtectedTable,
  isSQLInjectionAttempt,
  stripFlagValues,
} from "@/lib/sql-injection-detection";
import {
  hasExfiltratedCanary,
  type CanarySlug,
} from "@/lib/sql-injection-canary";
import { trackingBodySchema } from "@/lib/validation/schemas/tracking";

const CANARY_SLUG: CanarySlug = "x-forwarded-for-sql-injection";

export async function POST(request: NextRequest) {
  try {
    const parsed = await parseBody(request, trackingBodySchema);
    if (!parsed.success) return parsed.response;
    const { path, sessionId } = parsed.data;

    const forwardedFor = request.headers.get("x-forwarded-for");
    const ip = forwardedFor || request.headers.get("x-real-ip") || "unknown";

    const userAgent = request.headers.get("user-agent") || "";
    const visitPath = path || "/";
    const visitorSessionId = sessionId || null;

    if (forwardedFor && isAccessingProtectedTable(forwardedFor)) {
      return NextResponse.json(
        {
          error:
            "Access to the flags and hints tables is not allowed... Nice try though! The flag is hidden elsewhere...",
          success: false,
        },
        { status: 403 }
      );
    }

    // VULNERABLE: Using raw SQL with direct header value concatenation
    // This allows SQL injection through the X-Forwarded-For header
    const id = crypto.randomUUID();
    const query = `
      INSERT INTO visitor_logs (id, ip, userAgent, path, sessionId, createdAt)
      VALUES ('${id}', '${ip}', '${userAgent.replace(/'/g, "''")}', '${visitPath.replace(/'/g, "''")}', ${visitorSessionId ? `'${visitorSessionId}'` : "NULL"}, datetime('now'))
    `;

    let sqlError: string | null = null;
    try {
      await prisma.$queryRawUnsafe(query);
    } catch (error) {
      sqlError = error instanceof Error ? error.message : String(error);
      logger.error(
        { err: error, route: "/api/tracking" },
        "Error executing tracking query"
      );
    }

    // Scoped to the id this request generated: a rowid window would hand the
    // caller rows logged for other visitors, and with them a canary they never
    // extracted. The player reads their injection back through this row.
    const logged = stripFlagValues(
      await prisma.$queryRawUnsafe<Record<string, unknown>[]>(
        `SELECT * FROM visitor_logs WHERE id = '${id}'`
      )
    );

    const canary = await prisma.internalSecret.findUnique({
      where: { slug: CANARY_SLUG },
    });

    const response: {
      success: boolean;
      logged: Record<string, unknown>[];
      error?: string;
      flag?: string;
      message?: string;
    } = {
      success: sqlError === null,
      logged,
    };

    if (sqlError) {
      response.error = sqlError;
    }

    if (
      hasExfiltratedCanary(logged, canary, [
        ip,
        userAgent,
        visitPath,
        visitorSessionId ?? "",
      ])
    ) {
      const flag = await prisma.flag.findUnique({
        where: { slug: CANARY_SLUG },
      });
      if (flag) {
        response.flag = flag.flag;
        response.message =
          "Internal secret exfiltrated through the X-Forwarded-For header! Well done!";
      }
    } else if (forwardedFor && isSQLInjectionAttempt(forwardedFor)) {
      response.message =
        "SQL syntax detected in X-Forwarded-For." +
        " The flag tracks one specific internal secret, and it is not in the logged visit.";
    }

    return NextResponse.json(response);
  } catch (error) {
    logger.error({ err: error, route: "/api/tracking" }, "Error logging visit");
    return NextResponse.json({ error: "Failed to log visit" }, { status: 500 });
  }
}
