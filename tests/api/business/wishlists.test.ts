import {
  apiRequest,
  loginOrFail,
  authHeaders,
  TEST_USERS,
} from "../../helpers/api";

interface WishlistResponse {
  id: string;
  name: string;
  isPublic: boolean;
  createdAt: string;
  updatedAt: string;
  items: {
    id: string;
    addedAt: string;
    product: { id: string; name: string; price: number };
  }[];
}

describe("Wishlists (Business Logic)", () => {
  let aliceToken: string;

  beforeAll(async () => {
    aliceToken = await loginOrFail(
      TEST_USERS.alice.email,
      TEST_USERS.alice.password
    );
  });

  describe("POST /api/wishlists", () => {
    it("creates a new wishlist", async () => {
      const name = `Test Wishlist ${Date.now()}`;

      const { status, data } = await apiRequest<WishlistResponse>(
        "/api/wishlists",
        {
          method: "POST",
          headers: authHeaders(aliceToken),
          body: JSON.stringify({ name }),
        }
      );

      expect(status).toBe(201);
      expect(data.name).toBe(name);
      expect(data.id).toBeDefined();
      expect(data.isPublic).toBe(false);
      expect(data.items).toHaveLength(0);
    });

    it("trims whitespace from name", async () => {
      const { status, data } = await apiRequest<WishlistResponse>(
        "/api/wishlists",
        {
          method: "POST",
          headers: authHeaders(aliceToken),
          body: JSON.stringify({ name: "  Trimmed Name  " }),
        }
      );

      expect(status).toBe(201);
      expect(data.name).toBe("Trimmed Name");
    });

    it("rejects empty name", async () => {
      const { status: s1 } = await apiRequest("/api/wishlists", {
        method: "POST",
        headers: authHeaders(aliceToken),
        body: JSON.stringify({ name: "" }),
      });
      expect(s1).toBe(400);

      const { status: s2 } = await apiRequest("/api/wishlists", {
        method: "POST",
        headers: authHeaders(aliceToken),
        body: JSON.stringify({ name: "   " }),
      });
      expect(s2).toBe(400);

      const { status: s3 } = await apiRequest("/api/wishlists", {
        method: "POST",
        headers: authHeaders(aliceToken),
        body: JSON.stringify({}),
      });
      expect(s3).toBe(400);
    });

    it("requires authentication", async () => {
      const { status } = await apiRequest("/api/wishlists", {
        method: "POST",
        body: JSON.stringify({ name: "Unauthorized Wishlist" }),
      });

      expect(status).toBe(401);
    });
  });

  describe("GET /api/wishlists", () => {
    it("returns user wishlists", async () => {
      const { status, data } = await apiRequest<WishlistResponse[]>(
        "/api/wishlists",
        {
          headers: authHeaders(aliceToken),
        }
      );

      expect(status).toBe(200);
      expect(Array.isArray(data)).toBe(true);
      expect(data.length).toBeGreaterThan(0);

      const wishlist = data[0];
      expect(wishlist).toHaveProperty("id");
      expect(wishlist).toHaveProperty("name");
      expect(wishlist).toHaveProperty("isPublic");
      expect(wishlist).toHaveProperty("items");
    });

    it("requires authentication", async () => {
      const { status } = await apiRequest("/api/wishlists");
      expect(status).toBe(401);
    });
  });

  describe("DELETE /api/wishlists/:id", () => {
    it("deletes own wishlist", async () => {
      const { data: created } = await apiRequest<WishlistResponse>(
        "/api/wishlists",
        {
          method: "POST",
          headers: authHeaders(aliceToken),
          body: JSON.stringify({ name: `To Delete ${Date.now()}` }),
        }
      );

      const { status, data } = await apiRequest<{ success: boolean }>(
        `/api/wishlists/${created.id}`,
        {
          method: "DELETE",
          headers: authHeaders(aliceToken),
        }
      );

      expect(status).toBe(200);
      expect(data.success).toBe(true);
    });

    it("returns 404 for non-existent wishlist", async () => {
      const { status } = await apiRequest("/api/wishlists/non-existent-id", {
        method: "DELETE",
        headers: authHeaders(aliceToken),
      });

      expect(status).toBe(404);
    });

    it("prevents deleting another user's wishlist", async () => {
      const { data: created } = await apiRequest<WishlistResponse>(
        "/api/wishlists",
        {
          method: "POST",
          headers: authHeaders(aliceToken),
          body: JSON.stringify({ name: `Alice Only ${Date.now()}` }),
        }
      );

      const bobToken = await loginOrFail(
        TEST_USERS.bob.email,
        TEST_USERS.bob.password
      );

      const { status } = await apiRequest(`/api/wishlists/${created.id}`, {
        method: "DELETE",
        headers: authHeaders(bobToken),
      });

      expect(status).toBe(403);
    });
  });
});
