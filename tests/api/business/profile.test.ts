import {
  apiRequest,
  loginOrFail,
  authHeaders,
  TEST_USERS,
} from "../../helpers/api";

interface ProfileResponse {
  id: string;
  email: string;
  displayName: string | null;
  bio: string | null;
  role: string;
}

describe("User Profile (Business Logic)", () => {
  let aliceToken: string;

  beforeAll(async () => {
    aliceToken = await loginOrFail(
      TEST_USERS.alice.email,
      TEST_USERS.alice.password
    );
  });

  describe("GET /api/user/profile", () => {
    it("returns the authenticated user profile", async () => {
      const { status, data } = await apiRequest<ProfileResponse>(
        "/api/user/profile",
        { headers: authHeaders(aliceToken) }
      );

      expect(status).toBe(200);
      expect(data.email).toBe(TEST_USERS.alice.email);
      expect(data.role).toBe("CUSTOMER");
      expect(data.id).toBeDefined();
    });

    it("requires authentication", async () => {
      const { status } = await apiRequest("/api/user/profile");
      expect(status).toBe(401);
    });
  });

  describe("POST /api/user/profile", () => {
    it("updates display name", async () => {
      const displayName = `Alice_${Date.now()}`;

      const { status, data } = await apiRequest<{
        message: string;
        user: ProfileResponse;
      }>("/api/user/profile", {
        method: "POST",
        headers: {
          ...authHeaders(aliceToken),
          Referer: "http://localhost:3000/profile",
        },
        body: JSON.stringify({ displayName }),
      });

      expect(status).toBe(200);
      expect(data.message).toMatch(/updated/i);
      expect(data.user.displayName).toBe(displayName);
    });

    it("updates bio", async () => {
      const bio = "I love security testing!";

      const { status, data } = await apiRequest<{
        user: ProfileResponse;
      }>("/api/user/profile", {
        method: "POST",
        headers: {
          ...authHeaders(aliceToken),
          Referer: "http://localhost:3000/profile",
        },
        body: JSON.stringify({ bio }),
      });

      expect(status).toBe(200);
      expect(data.user.bio).toBe(bio);
    });

    it("updates both display name and bio at once", async () => {
      const displayName = `Alice_Both_${Date.now()}`;
      const bio = "Updated bio";

      const { status, data } = await apiRequest<{
        user: ProfileResponse;
      }>("/api/user/profile", {
        method: "POST",
        headers: {
          ...authHeaders(aliceToken),
          Referer: "http://localhost:3000/profile",
        },
        body: JSON.stringify({ displayName, bio }),
      });

      expect(status).toBe(200);
      expect(data.user.displayName).toBe(displayName);
      expect(data.user.bio).toBe(bio);
    });

    it("persists profile changes across requests", async () => {
      const displayName = `Persistent_${Date.now()}`;

      await apiRequest("/api/user/profile", {
        method: "POST",
        headers: {
          ...authHeaders(aliceToken),
          Referer: "http://localhost:3000/profile",
        },
        body: JSON.stringify({ displayName }),
      });

      const { data } = await apiRequest<ProfileResponse>("/api/user/profile", {
        headers: authHeaders(aliceToken),
      });

      expect(data.displayName).toBe(displayName);
    });

    it("requires authentication", async () => {
      const { status } = await apiRequest("/api/user/profile", {
        method: "POST",
        body: JSON.stringify({ displayName: "Hacker" }),
      });

      expect(status).toBe(401);
    });
  });
});
