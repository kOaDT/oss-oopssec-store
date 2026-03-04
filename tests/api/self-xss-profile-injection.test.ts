import {
  apiRequest,
  loginOrFail,
  authHeaders,
  TEST_USERS,
} from "../helpers/api";
import { FLAGS } from "../helpers/flags";

const XSS_BIO = '<img src=x onerror="alert(1)">';
const PLAIN_BIO = "Just a normal bio with no HTML.";

describe("Self-XSS Profile Injection", () => {
  let token: string;

  beforeAll(async () => {
    token = await loginOrFail(
      TEST_USERS.alice.email,
      TEST_USERS.alice.password
    );
  });

  afterAll(async () => {
    await apiRequest("/api/user/profile", {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ bio: "" }),
    });
  });

  describe("POST with HTML bio returns XSS flag", () => {
    it("returns flag when bio contains HTML tags", async () => {
      const { status, data } = await apiRequest<{
        flag?: string;
        user?: { bio: string };
      }>("/api/user/profile", {
        method: "POST",
        headers: {
          ...authHeaders(token),
          Referer: "http://localhost:3000/profile",
        },
        body: JSON.stringify({ bio: XSS_BIO }),
      });

      expect(status).toBe(200);
      expect(data).toHaveProperty("flag", FLAGS.SELF_XSS_PROFILE_INJECTION);
    });
  });

  describe("POST with plain text bio does NOT return flag", () => {
    it("returns 200 without flag for non-HTML bio", async () => {
      const { status, data } = await apiRequest<{ flag?: string }>(
        "/api/user/profile",
        {
          method: "POST",
          headers: {
            ...authHeaders(token),
            Referer: "http://localhost:3000/profile",
          },
          body: JSON.stringify({ bio: PLAIN_BIO }),
        }
      );

      expect(status).toBe(200);
      expect(data).not.toHaveProperty("flag");
    });
  });

  describe("Bio is stored unsanitized", () => {
    it("GET returns raw HTML in bio field after saving", async () => {
      await apiRequest("/api/user/profile", {
        method: "POST",
        headers: {
          ...authHeaders(token),
          Referer: "http://localhost:3000/profile",
        },
        body: JSON.stringify({ bio: XSS_BIO }),
      });

      const { status, data } = await apiRequest<{ bio: string }>(
        "/api/user/profile",
        { headers: authHeaders(token) }
      );

      expect(status).toBe(200);
      expect(data.bio).toBe(XSS_BIO);
    });
  });

  describe("Unauthenticated request is rejected", () => {
    it("returns 401 without auth cookie", async () => {
      const { status } = await apiRequest("/api/user/profile", {
        method: "POST",
        body: JSON.stringify({ bio: XSS_BIO }),
      });

      expect(status).toBe(401);
    });
  });
});
