import {
  apiRequest,
  loginOrFail,
  authHeaders,
  TEST_USERS,
  getFirstProductId,
} from "../../helpers/api";

interface ReviewResponse {
  id: string;
  productId: string;
  content: string;
  author: string;
  createdAt: string;
}

describe("Reviews (Business Logic)", () => {
  let aliceToken: string;
  let productId: string;

  beforeAll(async () => {
    aliceToken = await loginOrFail(
      TEST_USERS.alice.email,
      TEST_USERS.alice.password
    );
    productId = await getFirstProductId();
  });

  describe("POST /api/products/:id/reviews", () => {
    it("creates a review as an authenticated user", async () => {
      const { status, data } = await apiRequest<ReviewResponse>(
        `/api/products/${productId}/reviews`,
        {
          method: "POST",
          headers: authHeaders(aliceToken),
          body: JSON.stringify({ content: "Great product, highly recommend!" }),
        }
      );

      expect(status).toBe(201);
      expect(data.content).toBe("Great product, highly recommend!");
      expect(data.author).toBe(TEST_USERS.alice.email);
      expect(data.productId).toBe(productId);
      expect(data.id).toBeDefined();
      expect(data.createdAt).toBeDefined();
    });

    it("creates a review as anonymous (no auth)", async () => {
      const { status, data } = await apiRequest<ReviewResponse>(
        `/api/products/${productId}/reviews`,
        {
          method: "POST",
          body: JSON.stringify({ content: "Nice product!" }),
        }
      );

      expect(status).toBe(201);
      expect(data.author).toBe("anonymous");
      expect(data.content).toBe("Nice product!");
    });

    it("trims whitespace from content", async () => {
      const { status, data } = await apiRequest<ReviewResponse>(
        `/api/products/${productId}/reviews`,
        {
          method: "POST",
          body: JSON.stringify({ content: "  Trimmed review  " }),
        }
      );

      expect(status).toBe(201);
      expect(data.content).toBe("Trimmed review");
    });

    it("rejects empty content", async () => {
      const { status: s1 } = await apiRequest(
        `/api/products/${productId}/reviews`,
        {
          method: "POST",
          body: JSON.stringify({ content: "" }),
        }
      );
      expect(s1).toBe(400);

      const { status: s2 } = await apiRequest(
        `/api/products/${productId}/reviews`,
        {
          method: "POST",
          body: JSON.stringify({ content: "   " }),
        }
      );
      expect(s2).toBe(400);

      const { status: s3 } = await apiRequest(
        `/api/products/${productId}/reviews`,
        {
          method: "POST",
          body: JSON.stringify({}),
        }
      );
      expect(s3).toBe(400);
    });

    it("rejects review for non-existent product", async () => {
      const { status } = await apiRequest(
        "/api/products/non-existent-id/reviews",
        {
          method: "POST",
          body: JSON.stringify({ content: "A review" }),
        }
      );

      expect(status).toBe(404);
    });
  });

  describe("GET /api/products/:id/reviews", () => {
    it("returns reviews for a product", async () => {
      const { status, data } = await apiRequest<ReviewResponse[]>(
        `/api/products/${productId}/reviews`
      );

      expect(status).toBe(200);
      expect(Array.isArray(data)).toBe(true);
      expect(data.length).toBeGreaterThan(0);

      const review = data[0];
      expect(review).toHaveProperty("id");
      expect(review).toHaveProperty("content");
      expect(review).toHaveProperty("author");
      expect(review).toHaveProperty("createdAt");
    });

    it("returns reviews sorted by most recent first", async () => {
      const { data } = await apiRequest<ReviewResponse[]>(
        `/api/products/${productId}/reviews`
      );

      if (data.length >= 2) {
        const first = new Date(data[0].createdAt).getTime();
        const second = new Date(data[1].createdAt).getTime();
        expect(first).toBeGreaterThanOrEqual(second);
      }
    });

    it("returns 404 for non-existent product", async () => {
      const { status } = await apiRequest(
        "/api/products/non-existent-id/reviews"
      );

      expect(status).toBe(404);
    });
  });
});
