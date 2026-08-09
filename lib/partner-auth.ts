import { NextRequest } from "next/server";
import crypto from "crypto";
import {
  getPartnerKeyId,
  getPartnerPrivateKey,
  getPartnerTokenKey,
} from "./partner-keys";
import {
  PARTNER_TOKEN_ISSUER,
  PARTNER_TOKEN_SCOPE,
  PARTNER_TOKEN_TTL_SECONDS,
} from "./partner-directory";

/**
 * Token layer of the Partner API.
 *
 * v1 of the API issued HS256 tokens; v2 issues RS256. Both are still accepted
 * so integrations that have not migrated keep working until v1 is retired.
 */

/** `sub` is the only claim the verifier requires; a forged token is free to
 * omit the rest, so anything else is optional by construction. */
export interface PartnerTokenClaims {
  sub: string;
  iss?: string;
  scope?: string;
  iat?: number;
  exp?: number;
}

function encodeSegment(value: object): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function decodeSegment<T>(segment: string): T | null {
  try {
    return JSON.parse(Buffer.from(segment, "base64url").toString("utf-8")) as T;
  } catch {
    return null;
  }
}

export function issuePartnerToken(
  supplierId: string,
  scope: string = PARTNER_TOKEN_SCOPE
): string {
  const issuedAt = Math.floor(Date.now() / 1000);

  const header = encodeSegment({
    alg: "RS256",
    typ: "JWT",
    kid: getPartnerKeyId(),
  });
  const payload = encodeSegment({
    iss: PARTNER_TOKEN_ISSUER,
    sub: supplierId,
    scope,
    iat: issuedAt,
    exp: issuedAt + PARTNER_TOKEN_TTL_SECONDS,
  });

  const signature = crypto
    .sign("RSA-SHA256", Buffer.from(`${header}.${payload}`), {
      key: getPartnerPrivateKey(),
    })
    .toString("base64url");

  return `${header}.${payload}.${signature}`;
}

export function verifyPartnerToken(token: string): PartnerTokenClaims | null {
  const parts = token.split(".");
  if (parts.length !== 3) {
    return null;
  }

  const [header, payload, signature] = parts;
  const signingInput = `${header}.${payload}`;

  const algorithm = decodeSegment<{ alg?: string }>(header)?.alg;
  const key = getPartnerTokenKey();

  let signatureIsValid: boolean;
  try {
    if (algorithm === "RS256") {
      signatureIsValid = crypto.verify(
        "RSA-SHA256",
        Buffer.from(signingInput),
        { key },
        Buffer.from(signature, "base64url")
      );
    } else if (algorithm === "HS256") {
      signatureIsValid =
        crypto
          .createHmac("sha256", key)
          .update(signingInput)
          .digest("base64url") === signature;
    } else {
      return null;
    }
  } catch {
    return null;
  }

  if (!signatureIsValid) {
    return null;
  }

  const claims = decodeSegment<PartnerTokenClaims>(payload);
  if (!claims?.sub) {
    return null;
  }

  if (claims.exp && claims.exp < Math.floor(Date.now() / 1000)) {
    return null;
  }

  return claims;
}

export function readBearerToken(request: NextRequest): string | null {
  const header = request.headers.get("authorization");
  if (!header) {
    return null;
  }

  const [scheme, value] = header.split(" ");
  if (scheme?.toLowerCase() !== "bearer" || !value?.trim()) {
    return null;
  }

  return value.trim();
}
