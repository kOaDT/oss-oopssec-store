import { NextRequest, NextResponse } from "next/server";
import crypto from "crypto";

interface JWTPayload {
  id: string;
  email: string;
  role: string;
  exp: number;
  supportAccess?: boolean;
}

const JWT_SECRET = process.env.JWT_SECRET || "secret";

export function hashMD5(text: string): string {
  return crypto.createHash("md5").update(text).digest("hex");
}

function signHS256(data: string, secret: string): string {
  return crypto.createHmac("sha256", secret).update(data).digest("base64url");
}

export function createWeakJWT(payload: object): string {
  const header = Buffer.from(
    JSON.stringify({ alg: "HS256", typ: "JWT" })
  ).toString("base64url");
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = signHS256(`${header}.${body}`, JWT_SECRET);
  return `${header}.${body}.${signature}`;
}

export function decodeWeakJWT(token: string): JWTPayload | null {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) {
      return null;
    }

    const [header, body, signature] = parts;
    const expectedSignature = signHS256(`${header}.${body}`, JWT_SECRET);

    if (signature !== expectedSignature) {
      return null;
    }

    const payload = JSON.parse(
      Buffer.from(body, "base64url").toString("utf-8")
    ) as JWTPayload;

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
  const token = request.cookies.get("authToken")?.value;

  if (!token) {
    return null;
  }

  return decodeWeakJWT(token);
}

export function setAuthCookie(response: NextResponse, token: string): void {
  response.cookies.set("authToken", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 60 * 60 * 24 * 7,
    path: "/",
  });
}

export function clearAuthCookie(response: NextResponse): void {
  response.cookies.set("authToken", "", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 0,
    path: "/",
  });
}
