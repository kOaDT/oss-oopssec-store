import {
  apiRequest,
  loginOrFail,
  authHeaders,
  TEST_USERS,
} from "../helpers/api";
import { FLAGS } from "../helpers/flags";

const XSS_BIO = '<img src=x onerror="alert(1)">';

describe("CSRF Profile Takeover Chain", () => {
  let token: string;

  beforeAll(async () => {
    token = await loginOrFail(
      TEST_USERS.alice.email,
      TEST_USERS.alice.password
    );
  });

  afterEach(async () => {
    await apiRequest("/api/user/profile", {
      method: "POST",
      headers: {
        ...authHeaders(token),
        Referer: "http://localhost:3000/profile",
      },
      body: JSON.stringify({ bio: "" }),
    });

    // Drain any pending csrfExploited flag
    await apiRequest("/api/user/profile", {
      headers: authHeaders(token),
    });
  });

  describe("POST from evil Referer sets csrfExploited", () => {
    it("GET returns csrfFlag after POST with evil Referer", async () => {
      const postRes = await apiRequest("/api/user/profile", {
        method: "POST",
        headers: {
          ...authHeaders(token),
          Referer: "https://evil.com/attack",
        },
        body: JSON.stringify({ bio: XSS_BIO }),
      });
      expect(postRes.status).toBe(200);

      const { status, data } = await apiRequest<{ csrfFlag?: string }>(
        "/api/user/profile",
        { headers: authHeaders(token) }
      );

      expect(status).toBe(200);
      expect(data).toHaveProperty(
        "csrfFlag",
        FLAGS.CSRF_PROFILE_TAKEOVER_CHAIN
      );
    });
  });

  describe("POST from /profile Referer does NOT set csrfExploited", () => {
    it("GET returns no csrfFlag when POST came from /profile", async () => {
      await apiRequest("/api/user/profile", {
        method: "POST",
        headers: {
          ...authHeaders(token),
          Referer: "http://localhost:3000/profile",
        },
        body: JSON.stringify({ bio: XSS_BIO }),
      });

      const { status, data } = await apiRequest<{ csrfFlag?: string }>(
        "/api/user/profile",
        { headers: authHeaders(token) }
      );

      expect(status).toBe(200);
      expect(data).not.toHaveProperty("csrfFlag");
    });
  });

  describe("POST with no Referer sets csrfExploited", () => {
    it("GET returns csrfFlag after POST without Referer", async () => {
      await apiRequest("/api/user/profile", {
        method: "POST",
        headers: authHeaders(token),
        body: JSON.stringify({ bio: XSS_BIO }),
      });

      const { status, data } = await apiRequest<{ csrfFlag?: string }>(
        "/api/user/profile",
        { headers: authHeaders(token) }
      );

      expect(status).toBe(200);
      expect(data).toHaveProperty(
        "csrfFlag",
        FLAGS.CSRF_PROFILE_TAKEOVER_CHAIN
      );
    });
  });

  describe("csrfExploited resets after GET", () => {
    it("second GET does NOT return csrfFlag", async () => {
      await apiRequest("/api/user/profile", {
        method: "POST",
        headers: {
          ...authHeaders(token),
          Referer: "https://evil.com",
        },
        body: JSON.stringify({ bio: XSS_BIO }),
      });

      // First GET — should return the flag
      const first = await apiRequest<{ csrfFlag?: string }>(
        "/api/user/profile",
        { headers: authHeaders(token) }
      );
      expect(first.data).toHaveProperty("csrfFlag");

      // Second GET — flag should be gone
      const second = await apiRequest<{ csrfFlag?: string }>(
        "/api/user/profile",
        { headers: authHeaders(token) }
      );
      expect(second.data).not.toHaveProperty("csrfFlag");
    });
  });

  describe("csrfExploited field is not leaked in responses", () => {
    it("POST response does not contain csrfExploited", async () => {
      const { data } = await apiRequest<Record<string, unknown>>(
        "/api/user/profile",
        {
          method: "POST",
          headers: {
            ...authHeaders(token),
            Referer: "https://evil.com",
          },
          body: JSON.stringify({ bio: XSS_BIO }),
        }
      );

      expect(data).not.toHaveProperty("csrfExploited");
      if (data.user) {
        expect(data.user).not.toHaveProperty("csrfExploited");
      }
    });

    it("GET response does not contain csrfExploited", async () => {
      const { data } = await apiRequest<Record<string, unknown>>(
        "/api/user/profile",
        { headers: authHeaders(token) }
      );

      expect(data).not.toHaveProperty("csrfExploited");
    });
  });

  describe("Form-encoded POST works", () => {
    it("accepts application/x-www-form-urlencoded and updates bio", async () => {
      const { status, data } = await apiRequest<{
        user?: { bio: string };
      }>("/api/user/profile", {
        method: "POST",
        headers: {
          ...authHeaders(token),
          "Content-Type": "application/x-www-form-urlencoded",
          Referer: "http://localhost:3000/profile",
        },
        body: "bio=form+encoded+bio",
      });

      expect(status).toBe(200);
      expect(data.user?.bio).toBe("form encoded bio");
    });
  });
});
