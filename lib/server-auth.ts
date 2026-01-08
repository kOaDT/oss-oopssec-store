import { NextRequest } from "next/server";
import crypto from "crypto";

interface JWTPayload {
  id: string;
  email: string;
  role: string;
  exp: number;
}

export function hashMD5(text: string): string {
  return crypto.createHash("md5").update(text).digest("hex");
}

export function createWeakJWT(payload: object): string {
  const header = Buffer.from(
    JSON.stringify({ alg: "none", typ: "JWT" })
  ).toString("base64url");
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `${header}.${body}.`;
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
  const tokenFromHeader = authHeader?.replace("Bearer ", "") || null;
  const tokenFromCookie = request.cookies.get("authToken")?.value || null;
  const token = tokenFromHeader || tokenFromCookie;

  if (!token) {
    return null;
  }

  return decodeWeakJWT(token);
}
