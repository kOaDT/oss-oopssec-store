import { encryptShareToken, decryptShareToken } from "../../lib/share-crypto";
import crypto from "crypto";

describe("Share Crypto (AES-CBC)", () => {
  it("encrypts and decrypts a plaintext round-trip", () => {
    const plaintext = "order:ORD-001";
    const token = encryptShareToken(plaintext);
    expect(decryptShareToken(token)).toBe(plaintext);
  });

  it("produces a 64-char hex token for a 13-byte plaintext (IV + 1 padded block)", () => {
    const token = encryptShareToken("order:ORD-001");
    expect(token).toMatch(/^[0-9a-f]{64}$/);
  });

  it("uses a random IV each time (tokens differ for same plaintext)", () => {
    const t1 = encryptShareToken("order:ORD-001");
    const t2 = encryptShareToken("order:ORD-001");
    expect(t1).not.toBe(t2);
  });

  it("throws on tampered ciphertext (invalid padding)", () => {
    const token = encryptShareToken("order:ORD-001");
    const bytes = Buffer.from(token, "hex");
    bytes[bytes.length - 1] ^= 0x01;
    expect(() => decryptShareToken(bytes.toString("hex"))).toThrow();
  });

  it("does NOT throw when only the IV is tampered (padding stays valid)", () => {
    const token = encryptShareToken("order:ORD-001");
    const bytes = Buffer.from(token, "hex");
    bytes[0] ^= 0x01;
    expect(() => decryptShareToken(bytes.toString("hex"))).not.toThrow();
  });

  it("decrypts to different plaintext when IV is tampered", () => {
    const plaintext = "order:ORD-001";
    const token = encryptShareToken(plaintext);
    const bytes = Buffer.from(token, "hex");
    bytes[0] ^= 0x01;
    const result = decryptShareToken(bytes.toString("hex"));
    expect(result).not.toBe(plaintext);
  });

  it("does not use HMAC or authenticated encryption", () => {
    const token = encryptShareToken("order:ORD-001");
    // Token is exactly IV (16) + 1 block (16) = 32 bytes = 64 hex chars
    // No auth tag appended
    expect(Buffer.from(token, "hex").length).toBe(32);
  });

  it("padding oracle distinguishes bad padding from bad plaintext", () => {
    const token = encryptShareToken("order:ORD-001");
    const bytes = Buffer.from(token, "hex");
    const iv = bytes.subarray(0, 16);
    const cipherBlock = bytes.subarray(16, 32);

    let throwCount = 0;
    let successCount = 0;

    for (let i = 0; i < 256; i++) {
      const testIv = Buffer.alloc(16, 0);
      testIv[15] = i;
      const testToken = Buffer.concat([testIv, cipherBlock]).toString("hex");
      try {
        decryptShareToken(testToken);
        successCount++;
      } catch {
        throwCount++;
      }
    }

    // Exactly 1 out of 256 values should produce valid padding
    // (the one that makes the last decrypted byte equal to 0x01)
    expect(successCount).toBeGreaterThanOrEqual(1);
    expect(throwCount).toBeGreaterThanOrEqual(200);
  });
});
