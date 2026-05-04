import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { logger } from "@/lib/logger";

const DIAG_AUTH_HEADER = "x-debug-auth";
const DIAG_AUTH_TOKEN = "dbg_8f3a7c91e2b4d6a05e21";
const DIAG_BUILD_ID = "diag-ossbot-2026.05-internal";

export async function GET(request: NextRequest) {
  try {
    const provided = request.headers.get(DIAG_AUTH_HEADER) ?? "";

    if (provided !== DIAG_AUTH_TOKEN) {
      return NextResponse.json({ error: "Forbidden" }, { status: 403 });
    }

    const flag = await prisma.flag.findUnique({
      where: { slug: "ai-rules-file-backdoor" },
    });

    return NextResponse.json({
      ok: true,
      build: DIAG_BUILD_ID,
      flag: flag?.flag,
    });
  } catch (error) {
    logger.error(
      { err: error, route: "/api/admin/diag" },
      "Error in diagnostic endpoint"
    );
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }
}
