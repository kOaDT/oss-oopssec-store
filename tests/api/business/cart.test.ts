import {
  apiRequest,
  loginOrFail,
  authHeaders,
  TEST_USERS,
  getFirstProductId,
} from "../../helpers/api";

interface CartResponse {
  cartItems: {
    id: string;
    productId: string;
    quantity: number;
    product: { id: string; name: string; price: number };
  }[];
  total: number;
}

describe("Cart (Business Logic)", () => {
  let aliceToken: string;
  let productId: string;

  beforeAll(async () => {
    aliceToken = await loginOrFail(
      TEST_USERS.alice.email,
      TEST_USERS.alice.password
    );
    productId = await getFirstProductId();
  });

  describe("POST /api/cart/add", () => {
    it("adds a product to the cart", async () => {
      const { status, data } = await apiRequest<{ success: boolean }>(
        "/api/cart/add",
        {
          method: "POST",
          headers: authHeaders(aliceToken),
          body: JSON.stringify({ productId, quantity: 1 }),
        }
      );

      expect(status).toBe(200);
      expect(data.success).toBe(true);
    });

    it("increments quantity when adding the same product again", async () => {
      const { data: cartBefore } = await apiRequest<CartResponse>("/api/cart", {
        headers: authHeaders(aliceToken),
      });
      const itemBefore = cartBefore.cartItems.find(
        (i) => i.productId === productId
      );
      const qtyBefore = itemBefore?.quantity ?? 0;

      await apiRequest("/api/cart/add", {
        method: "POST",
        headers: authHeaders(aliceToken),
        body: JSON.stringify({ productId, quantity: 2 }),
      });

      const { data: cartAfter } = await apiRequest<CartResponse>("/api/cart", {
        headers: authHeaders(aliceToken),
      });
      const itemAfter = cartAfter.cartItems.find(
        (i) => i.productId === productId
      );

      expect(itemAfter).toBeDefined();
      expect(itemAfter!.quantity).toBe(qtyBefore + 2);
    });

    it("rejects adding without productId or quantity", async () => {
      const { status: s1 } = await apiRequest("/api/cart/add", {
        method: "POST",
        headers: authHeaders(aliceToken),
        body: JSON.stringify({ quantity: 1 }),
      });
      expect(s1).toBe(400);

      const { status: s2 } = await apiRequest("/api/cart/add", {
        method: "POST",
        headers: authHeaders(aliceToken),
        body: JSON.stringify({ productId }),
      });
      expect(s2).toBe(400);
    });

    it("rejects adding with invalid quantity", async () => {
      const { status } = await apiRequest("/api/cart/add", {
        method: "POST",
        headers: authHeaders(aliceToken),
        body: JSON.stringify({ productId, quantity: 0 }),
      });

      expect(status).toBe(400);
    });

    it("rejects adding a non-existent product", async () => {
      const { status } = await apiRequest("/api/cart/add", {
        method: "POST",
        headers: authHeaders(aliceToken),
        body: JSON.stringify({ productId: "fake-product-id", quantity: 1 }),
      });

      expect(status).toBe(404);
    });

    it("requires authentication", async () => {
      const { status } = await apiRequest("/api/cart/add", {
        method: "POST",
        body: JSON.stringify({ productId, quantity: 1 }),
      });

      expect(status).toBe(401);
    });
  });

  describe("GET /api/cart", () => {
    it("returns the user cart with items and total", async () => {
      const { status, data } = await apiRequest<CartResponse>("/api/cart", {
        headers: authHeaders(aliceToken),
      });

      expect(status).toBe(200);
      expect(Array.isArray(data.cartItems)).toBe(true);
      expect(typeof data.total).toBe("number");

      if (data.cartItems.length > 0) {
        const item = data.cartItems[0];
        expect(item).toHaveProperty("id");
        expect(item).toHaveProperty("productId");
        expect(item).toHaveProperty("quantity");
        expect(item.product).toHaveProperty("name");
        expect(item.product).toHaveProperty("price");
      }
    });

    it("returns empty cart for user with no items", async () => {
      const bobToken = await loginOrFail(
        TEST_USERS.bob.email,
        TEST_USERS.bob.password
      );

      const { status, data } = await apiRequest<CartResponse>("/api/cart", {
        headers: authHeaders(bobToken),
      });

      expect(status).toBe(200);
      expect(data.total).toBe(0);
      expect(data.cartItems).toHaveLength(0);
    });

    it("requires authentication", async () => {
      const { status } = await apiRequest("/api/cart");
      expect(status).toBe(401);
    });
  });

  describe("PATCH /api/cart/items/:id", () => {
    it("updates cart item quantity", async () => {
      const { data: cart } = await apiRequest<CartResponse>("/api/cart", {
        headers: authHeaders(aliceToken),
      });
      const cartItem = cart.cartItems[0];
      if (!cartItem) return;

      const { status, data } = await apiRequest<{
        success: boolean;
        cartItem: { quantity: number };
      }>(`/api/cart/items/${cartItem.id}`, {
        method: "PATCH",
        headers: authHeaders(aliceToken),
        body: JSON.stringify({ quantity: 5 }),
      });

      expect(status).toBe(200);
      expect(data.success).toBe(true);
      expect(data.cartItem.quantity).toBe(5);
    });

    it("rejects invalid quantity", async () => {
      const { data: cart } = await apiRequest<CartResponse>("/api/cart", {
        headers: authHeaders(aliceToken),
      });
      const cartItem = cart.cartItems[0];
      if (!cartItem) return;

      const { status } = await apiRequest(`/api/cart/items/${cartItem.id}`, {
        method: "PATCH",
        headers: authHeaders(aliceToken),
        body: JSON.stringify({ quantity: 0 }),
      });

      expect(status).toBe(400);
    });

    it("returns 404 for non-existent cart item", async () => {
      const { status } = await apiRequest("/api/cart/items/non-existent-id", {
        method: "PATCH",
        headers: authHeaders(aliceToken),
        body: JSON.stringify({ quantity: 1 }),
      });

      expect(status).toBe(404);
    });
  });

  describe("DELETE /api/cart/items/:id", () => {
    it("removes item from cart", async () => {
      await apiRequest("/api/cart/add", {
        method: "POST",
        headers: authHeaders(aliceToken),
        body: JSON.stringify({ productId, quantity: 1 }),
      });

      const { data: cart } = await apiRequest<CartResponse>("/api/cart", {
        headers: authHeaders(aliceToken),
      });
      const cartItem = cart.cartItems.find((i) => i.productId === productId);
      expect(cartItem).toBeDefined();

      const { status, data } = await apiRequest<{ success: boolean }>(
        `/api/cart/items/${cartItem!.id}`,
        {
          method: "DELETE",
          headers: authHeaders(aliceToken),
        }
      );

      expect(status).toBe(200);
      expect(data.success).toBe(true);

      const { data: cartAfter } = await apiRequest<CartResponse>("/api/cart", {
        headers: authHeaders(aliceToken),
      });
      const deletedItem = cartAfter.cartItems.find(
        (i) => i.id === cartItem!.id
      );
      expect(deletedItem).toBeUndefined();
    });

    it("returns 404 for non-existent cart item", async () => {
      const { status } = await apiRequest("/api/cart/items/non-existent-id", {
        method: "DELETE",
        headers: authHeaders(aliceToken),
      });

      expect(status).toBe(404);
    });
  });
});
