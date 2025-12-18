import { NextRequest } from "next/server";

interface JWTPayload {
  id: string;
  email: string;
  role: string;
  exp: number;
}

export function decodeWeakJWT(token: string): JWTPayload | null {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) {
      return null;
    }

    const body = Buffer.from(parts[1], "base64url").toString("utf-8");
    const payload = JSON.parse(body) as JWTPayload;

    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

export async function getAuthenticatedUser(
  request: NextRequest
): Promise<JWTPayload | null> {
  const authHeader = request.headers.get("authorization");
  const token = authHeader?.replace("Bearer ", "") || null;

  if (!token) {
    return null;
  }

  return decodeWeakJWT(token);
}
