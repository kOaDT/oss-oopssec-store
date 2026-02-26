import { hashMD5 } from "../../lib/server-auth";

describe("Insecure Password Reset Token Generation", () => {
  it("generates a predictable token from email and timestamp", () => {
    const email = "admin@oss.com";
    const timestamp = 1700000000;

    const token = hashMD5(email + timestamp);

    expect(token).toBe(hashMD5("admin@oss.com1700000000"));
    expect(token).toMatch(/^[a-f0-9]{32}$/);
  });

  it("produces the same token for the same email and timestamp", () => {
    const email = "alice@example.com";
    const timestamp = 1700000000;

    const token1 = hashMD5(email + timestamp);
    const token2 = hashMD5(email + timestamp);

    expect(token1).toBe(token2);
  });

  it("produces different tokens for different emails with same timestamp", () => {
    const timestamp = 1700000000;

    const token1 = hashMD5("alice@example.com" + timestamp);
    const token2 = hashMD5("admin@oss.com" + timestamp);

    expect(token1).not.toBe(token2);
  });

  it("produces different tokens for same email with different timestamps", () => {
    const email = "admin@oss.com";

    const token1 = hashMD5(email + 1700000000);
    const token2 = hashMD5(email + 1700000001);

    expect(token1).not.toBe(token2);
  });
});
