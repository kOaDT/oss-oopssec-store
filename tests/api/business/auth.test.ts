import {
  apiRequest,
  extractAuthTokenFromHeaders,
  TEST_USERS,
} from "../../helpers/api";

describe("Authentication (Business Logic)", () => {
  const uniqueEmail = `test-${Date.now()}@example.com`;
  const password = "testpassword123";

  describe("POST /api/auth/signup", () => {
    it("creates a new account and returns user data with auth cookie", async () => {
      const { status, data, headers } = await apiRequest<{
        user: { id: string; email: string; role: string };
      }>("/api/auth/signup", {
        method: "POST",
        body: JSON.stringify({ email: uniqueEmail, password }),
      });

      expect(status).toBe(200);
      expect(data.user).toMatchObject({
        email: uniqueEmail,
        role: "CUSTOMER",
      });
      expect(data.user.id).toBeDefined();

      const token = extractAuthTokenFromHeaders(headers);
      expect(token).not.toBeNull();
    });

    it("rejects duplicate email registration", async () => {
      const { status, data } = await apiRequest<{ error: string }>(
        "/api/auth/signup",
        {
          method: "POST",
          body: JSON.stringify({ email: uniqueEmail, password }),
        }
      );

      expect(status).toBe(409);
      expect(data.error).toMatch(/already registered/i);
    });

    it("rejects signup without email or password", async () => {
      const { status: s1 } = await apiRequest("/api/auth/signup", {
        method: "POST",
        body: JSON.stringify({ email: "no-pass@example.com" }),
      });
      expect(s1).toBe(400);

      const { status: s2 } = await apiRequest("/api/auth/signup", {
        method: "POST",
        body: JSON.stringify({ password: "nopass" }),
      });
      expect(s2).toBe(400);
    });
  });

  describe("POST /api/auth/login", () => {
    it("logs in with valid credentials and returns auth cookie", async () => {
      const { status, data, headers } = await apiRequest<{
        user: { id: string; email: string; role: string };
      }>("/api/auth/login", {
        method: "POST",
        body: JSON.stringify({
          email: TEST_USERS.alice.email,
          password: TEST_USERS.alice.password,
        }),
      });

      expect(status).toBe(200);
      expect(data.user.email).toBe(TEST_USERS.alice.email);
      expect(data.user.role).toBe("CUSTOMER");

      const token = extractAuthTokenFromHeaders(headers);
      expect(token).not.toBeNull();
    });

    it("rejects invalid password", async () => {
      const { status, data } = await apiRequest<{ error: string }>(
        "/api/auth/login",
        {
          method: "POST",
          body: JSON.stringify({
            email: TEST_USERS.alice.email,
            password: "wrongpassword",
          }),
        }
      );

      expect(status).toBe(401);
      expect(data.error).toBeDefined();
    });

    it("rejects non-existent email", async () => {
      const { status } = await apiRequest("/api/auth/login", {
        method: "POST",
        body: JSON.stringify({
          email: "nonexistent@example.com",
          password: "whatever",
        }),
      });

      expect(status).toBe(401);
    });

    it("rejects login without credentials", async () => {
      const { status } = await apiRequest("/api/auth/login", {
        method: "POST",
        body: JSON.stringify({}),
      });

      expect(status).toBe(400);
    });

    it("admin login returns admin role", async () => {
      const { status, data } = await apiRequest<{
        user: { role: string };
      }>("/api/auth/login", {
        method: "POST",
        body: JSON.stringify({
          email: TEST_USERS.admin.email,
          password: TEST_USERS.admin.password,
        }),
      });

      expect(status).toBe(200);
      expect(data.user.role).toBe("ADMIN");
    });
  });

  describe("POST /api/auth/logout", () => {
    it("clears the auth cookie on logout", async () => {
      const { status, data } = await apiRequest<{ success: boolean }>(
        "/api/auth/logout",
        { method: "POST" }
      );

      expect(status).toBe(200);
      expect(data.success).toBe(true);
    });
  });
});
