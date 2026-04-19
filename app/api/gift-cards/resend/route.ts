import { NextRequest, NextResponse } from "next/server";
import { withAuth } from "@/lib/server-auth";

export const POST = withAuth(async (_request: NextRequest, _context, _user) => {
  return NextResponse.json(
    { error: "Email service temporarily unavailable. Please try again later." },
    { status: 503 }
  );
});
