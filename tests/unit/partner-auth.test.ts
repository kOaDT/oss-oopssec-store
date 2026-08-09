import crypto from "crypto";
import fs from "fs";
import os from "os";
import path from "path";
import { issuePartnerToken, verifyPartnerToken } from "../../lib/partner-auth";
import { getPartnerTokenKey } from "../../lib/partner-keys";
import {
  PARTNER_TOKEN_ISSUER,
  PARTNER_TOKEN_SCOPE,
  SANDBOX_SUPPLIER_ID,
} from "../../lib/partner-directory";

// Redirect the key material to a throwaway directory so running the suite never
// touches the developer's real signing key. Safe to do after the imports: the
// pair is materialised lazily, on the first call that needs it.
process.env.PARTNER_SIGNING_KEY_PATH = path.join(
  fs.mkdtempSync(path.join(os.tmpdir(), "oopssec-partner-key-")),
  "partner-signing-key.pem"
);

/**
 * These tests pin the *vulnerable* behaviour of the Partner API verifier: it
 * dispatches on the `alg` header and feeds both branches the same key. Pinning
 * the fix instead would leave the challenge free to rot.
 */

const encode = (value: object) =>
  Buffer.from(JSON.stringify(value)).toString("base64url");

function claimsFor(sub: string, overrides: Record<string, unknown> = {}) {
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: PARTNER_TOKEN_ISSUER,
    sub,
    scope: PARTNER_TOKEN_SCOPE,
    iat: now,
    exp: now + 3600,
    ...overrides,
  };
}

function signHS256(claims: object, secret: string): string {
  const header = encode({ alg: "HS256", typ: "JWT" });
  const payload = encode(claims);
  const signature = crypto
    .createHmac("sha256", secret)
    .update(`${header}.${payload}`)
    .digest("base64url");
  return `${header}.${payload}.${signature}`;
}

describe("Partner API token verifier", () => {
  describe("legitimate RS256 tokens", () => {
    it("issues tokens whose header advertises RS256 and a key id", () => {
      const token = issuePartnerToken(SANDBOX_SUPPLIER_ID);
      const header = JSON.parse(
        Buffer.from(token.split(".")[0], "base64url").toString()
      );

      expect(header.alg).toBe("RS256");
      expect(header.typ).toBe("JWT");
      expect(typeof header.kid).toBe("string");
    });

    it("roundtrips its own tokens", () => {
      const claims = verifyPartnerToken(issuePartnerToken(SANDBOX_SUPPLIER_ID));

      expect(claims).not.toBeNull();
      expect(claims!.sub).toBe(SANDBOX_SUPPLIER_ID);
      expect(claims!.iss).toBe(PARTNER_TOKEN_ISSUER);
      expect(claims!.scope).toBe(PARTNER_TOKEN_SCOPE);
    });

    it("rejects a payload tampered with after signing", () => {
      const [header, , signature] =
        issuePartnerToken(SANDBOX_SUPPLIER_ID).split(".");
      const tampered = encode(claimsFor("SUP-LETTUCE"));

      expect(
        verifyPartnerToken(`${header}.${tampered}.${signature}`)
      ).toBeNull();
    });

    it("rejects an expired token", () => {
      const token = issuePartnerToken(SANDBOX_SUPPLIER_ID);
      const [header, payload, signature] = token.split(".");
      const claims = JSON.parse(Buffer.from(payload, "base64url").toString());

      expect(
        verifyPartnerToken(
          `${header}.${encode({ ...claims, exp: 1 })}.${signature}`
        )
      ).toBeNull();
    });
  });

  describe("algorithm confusion (RS256 → HS256)", () => {
    it("uses a PEM-encoded public key as its verification key", () => {
      const key = getPartnerTokenKey();

      expect(key.startsWith("-----BEGIN PUBLIC KEY-----")).toBe(true);
      expect(key.endsWith("-----END PUBLIC KEY-----\n")).toBe(true);
    });

    it("accepts an HS256 token signed with the public key as HMAC secret", () => {
      const forged = signHS256(
        claimsFor(SANDBOX_SUPPLIER_ID),
        getPartnerTokenKey()
      );
      const claims = verifyPartnerToken(forged);

      expect(claims).not.toBeNull();
      expect(claims!.sub).toBe(SANDBOX_SUPPLIER_ID);
    });

    it("lets a forged sub claim impersonate any supplier", () => {
      for (const supplierId of ["SUP-001", "SUP-LETTUCE", "SUP-BRIE"]) {
        const claims = verifyPartnerToken(
          signHS256(claimsFor(supplierId), getPartnerTokenKey())
        );

        expect([supplierId, claims?.sub]).toEqual([supplierId, supplierId]);
      }
    });

    it("requires the exact PEM bytes, trailing newline included", () => {
      const key = getPartnerTokenKey();
      const claims = claimsFor("SUP-LETTUCE");

      expect(verifyPartnerToken(signHS256(claims, key.trimEnd()))).toBeNull();
      expect(verifyPartnerToken(signHS256(claims, key))).not.toBeNull();
    });

    it("still expires forged tokens", () => {
      const forged = signHS256(
        claimsFor("SUP-LETTUCE", { exp: Math.floor(Date.now() / 1000) - 1 }),
        getPartnerTokenKey()
      );

      expect(verifyPartnerToken(forged)).toBeNull();
    });

    it("lets a forgery omit exp entirely and never expire", () => {
      const claims = claimsFor("SUP-LETTUCE") as Record<string, unknown>;
      delete claims.exp;

      expect(
        verifyPartnerToken(signHS256(claims, getPartnerTokenKey()))?.sub
      ).toBe("SUP-LETTUCE");
    });
  });

  describe("rejected tokens", () => {
    it("rejects HS256 signed with anything other than the verification key", () => {
      for (const secret of ["secret", "changeme", "SUP-LETTUCE"]) {
        expect(
          verifyPartnerToken(signHS256(claimsFor("SUP-LETTUCE"), secret))
        ).toBeNull();
      }
    });

    it("rejects unsigned and unknown algorithms", () => {
      const payload = encode(claimsFor("SUP-LETTUCE"));

      for (const alg of ["none", "None", "RS512", "HS512", ""]) {
        const header = encode({ alg, typ: "JWT" });
        expect([alg, verifyPartnerToken(`${header}.${payload}.`)]).toEqual([
          alg,
          null,
        ]);
      }
    });

    it("rejects a token with no sub claim", () => {
      const claims = claimsFor("SUP-LETTUCE") as Record<string, unknown>;
      delete claims.sub;

      expect(
        verifyPartnerToken(signHS256(claims, getPartnerTokenKey()))
      ).toBeNull();
    });

    it("rejects malformed tokens", () => {
      for (const token of ["", "onlyonepart", "two.parts", "a.b.c.d", "..."]) {
        expect([token, verifyPartnerToken(token)]).toEqual([token, null]);
      }
    });
  });
});
