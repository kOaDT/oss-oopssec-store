import { apiRequest, getFirstProductId } from "../../helpers/api";

describe("Products (Business Logic)", () => {
  describe("GET /api/products", () => {
    it("returns a list of products", async () => {
      const { status, data } =
        await apiRequest<
          { id: string; name: string; price: number; imageUrl: string }[]
        >("/api/products");

      expect(status).toBe(200);
      expect(Array.isArray(data)).toBe(true);
      expect(data.length).toBeGreaterThan(0);

      const product = data[0];
      expect(product).toHaveProperty("id");
      expect(product).toHaveProperty("name");
      expect(product).toHaveProperty("price");
      expect(typeof product.price).toBe("number");
      expect(product.price).toBeGreaterThan(0);
    });
  });

  describe("GET /api/products/:id", () => {
    it("returns a single product by ID", async () => {
      const productId = await getFirstProductId();

      const { status, data } = await apiRequest<{
        id: string;
        name: string;
        price: number;
        description: string | null;
        imageUrl: string;
      }>(`/api/products/${productId}`);

      expect(status).toBe(200);
      expect(data.id).toBe(productId);
      expect(data.name).toBeDefined();
      expect(typeof data.price).toBe("number");
    });

    it("returns 404 for non-existent product", async () => {
      const { status, data } = await apiRequest<{ error: string }>(
        "/api/products/non-existent-id"
      );

      expect(status).toBe(404);
      expect(data.error).toMatch(/not found/i);
    });
  });
});
