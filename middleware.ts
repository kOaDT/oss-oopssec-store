import { NextRequest, NextResponse } from "next/server";

function decodeJWT(token: string): Record<string, unknown> | null {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;

    const payload = JSON.parse(
      atob(parts[1].replace(/-/g, "+").replace(/_/g, "/"))
    );

    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

export function middleware(request: NextRequest) {
  const authToken = request.cookies.get("authToken")?.value;
  const payload = authToken ? decodeJWT(authToken) : null;

  if (!payload) {
    return NextResponse.redirect(new URL("/login", request.url));
  }

  if (payload.role !== "ADMIN") {
    return NextResponse.redirect(new URL("/login", request.url));
  }

  console.log("test");

  return NextResponse.next();
}

export const config = {
  matcher: ["/monitoring/internal-status"],
};
