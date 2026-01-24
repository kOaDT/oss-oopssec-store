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
    "||",
  ];
  const upperInput = input.toUpperCase();
  return sqlKeywords.some((keyword) => upperInput.includes(keyword));
};

const isAccessingFlagsTable = (input: string): boolean => {
  const upperInput = input.toUpperCase();
  const normalizedInput = upperInput.replace(/\s+/g, " ");
  return (
    normalizedInput.includes("FROM FLAGS") ||
    normalizedInput.includes("FROM`FLAGS`") ||
    normalizedInput.includes('FROM"FLAGS"') ||
    normalizedInput.includes("JOIN FLAGS") ||
    normalizedInput.includes("JOIN`FLAGS`") ||
    normalizedInput.includes('JOIN"FLAGS"') ||
    normalizedInput.includes("FLAGS WHERE") ||
    normalizedInput.includes("FLAGS.") ||
    /FLAGS\s*[,\s]/.test(normalizedInput)
  );
};

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { path, sessionId } = body;

    const forwardedFor = request.headers.get("x-forwarded-for");
    const ip = forwardedFor || request.headers.get("x-real-ip") || "unknown";

    const userAgent = request.headers.get("user-agent") || "";
    const visitPath = path || "/";
    const visitorSessionId = sessionId || null;

    // Check for SQL injection in the X-Forwarded-For header
    let flag: string | null = null;
    let sqlInjectionDetected = false;

    if (forwardedFor) {
      // Block access to flags table
      if (isAccessingFlagsTable(forwardedFor)) {
        return NextResponse.json(
          {
            error:
              "Access to flags table is not allowed... Nice try though! The flag is hidden elsewhere...",
            success: false,
          },
          { status: 403 }
        );
      }

      // Detect SQL injection attempt
      sqlInjectionDetected = isSQLInjectionAttempt(forwardedFor);
      if (sqlInjectionDetected) {
        const sqlInjectionFlag = await prisma.flag.findUnique({
          where: { slug: "x-forwarded-for-sql-injection" },
        });
        if (sqlInjectionFlag) {
          flag = sqlInjectionFlag.flag;
        }
      }
    }

    // VULNERABLE: Using raw SQL with direct header value concatenation
    // This allows SQL injection through the X-Forwarded-For header
    const id = crypto.randomUUID();
    const query = `
      INSERT INTO visitor_logs (id, ip, userAgent, path, sessionId, createdAt)
      VALUES ('${id}', '${ip}', '${userAgent.replace(/'/g, "''")}', '${visitPath.replace(/'/g, "''")}', ${visitorSessionId ? `'${visitorSessionId}'` : "NULL"}, datetime('now'))
    `;

    try {
      await prisma.$queryRawUnsafe(query);
    } catch (error) {
      // Log error but don't expose details
      console.error("Error executing tracking query:", error);
    }

    // Build response
    const response: {
      success: boolean;
      flag?: string;
      message?: string;
    } = {
      success: true,
    };

    if (sqlInjectionDetected && flag) {
      response.flag = flag;
      response.message =
        "SQL injection detected in X-Forwarded-For header! Well done!";
    }

    return NextResponse.json(response);
  } catch (error) {
    console.error("Error logging visit:", error);
    return NextResponse.json({ error: "Failed to log visit" }, { status: 500 });
  }
}
