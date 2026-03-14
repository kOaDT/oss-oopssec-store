import {
  apiRequest,
  loginOrFail,
  authHeaders,
  TEST_USERS,
  getFirstProductId,
} from "../../helpers/api";

interface CartResponse {
  cartItems: { id: string; productId: string; quantity: number }[];
  total: number;
}

interface OrderResponse {
  id: string;
  total: number;
  status: string;
  flag?: string;
}

interface OrderDetailResponse {
  id: string;
  total: number;
  status: string;
  customerName: string;
  customerEmail: string;
  deliveryAddress: {
    street: string;
    city: string;
    state: string;
    zipCode: string;
    country: string;
  };
}

describe("Orders (Business Logic)", () => {
  let aliceToken: string;
  let productId: string;

  beforeAll(async () => {
    aliceToken = await loginOrFail(
      TEST_USERS.alice.email,
      TEST_USERS.alice.password
    );
    productId = await getFirstProductId();
  });

  describe("POST /api/orders", () => {
    it("creates an order from the cart with correct total", async () => {
      await apiRequest("/api/cart/add", {
        method: "POST",
        headers: authHeaders(aliceToken),
        body: JSON.stringify({ productId, quantity: 1 }),
      });

      const { data: cart } = await apiRequest<CartResponse>("/api/cart", {
        headers: authHeaders(aliceToken),
      });
      expect(cart.cartItems.length).toBeGreaterThan(0);

      const { status, data } = await apiRequest<OrderResponse>("/api/orders", {
        method: "POST",
        headers: authHeaders(aliceToken),
        body: JSON.stringify({ total: cart.total }),
      });

      expect(status).toBe(200);
      expect(data.id).toMatch(/^ORD-\d{3,}$/);
      expect(data.total).toBe(cart.total);
      expect(data.status).toBe("PENDING");
      expect(data.flag).toBeUndefined();
    });

    it("clears the cart after placing an order", async () => {
      await apiRequest("/api/cart/add", {
        method: "POST",
        headers: authHeaders(aliceToken),
        body: JSON.stringify({ productId, quantity: 1 }),
      });

      const { data: cartBefore } = await apiRequest<CartResponse>("/api/cart", {
        headers: authHeaders(aliceToken),
      });
      expect(cartBefore.cartItems.length).toBeGreaterThan(0);

      await apiRequest("/api/orders", {
        method: "POST",
        headers: authHeaders(aliceToken),
        body: JSON.stringify({ total: cartBefore.total }),
      });

      const { data: cartAfter } = await apiRequest<CartResponse>("/api/cart", {
        headers: authHeaders(aliceToken),
      });
      expect(cartAfter.cartItems).toHaveLength(0);
      expect(cartAfter.total).toBe(0);
    });

    it("rejects order with empty cart", async () => {
      const { data: cart } = await apiRequest<CartResponse>("/api/cart", {
        headers: authHeaders(aliceToken),
      });

      if (cart.cartItems.length > 0) {
        for (const item of cart.cartItems) {
          await apiRequest(`/api/cart/items/${item.id}`, {
            method: "DELETE",
            headers: authHeaders(aliceToken),
          });
        }
      }

      const { status, data } = await apiRequest<{ error: string }>(
        "/api/orders",
        {
          method: "POST",
          headers: authHeaders(aliceToken),
          body: JSON.stringify({ total: 10 }),
        }
      );

      expect(status).toBe(400);
      expect(data.error).toMatch(/cart is empty/i);
    });

    it("rejects order with invalid total", async () => {
      const { status: s1 } = await apiRequest("/api/orders", {
        method: "POST",
        headers: authHeaders(aliceToken),
        body: JSON.stringify({ total: 0 }),
      });
      expect(s1).toBe(400);

      const { status: s2 } = await apiRequest("/api/orders", {
        method: "POST",
        headers: authHeaders(aliceToken),
        body: JSON.stringify({ total: -5 }),
      });
      expect(s2).toBe(400);
    });

    it("requires authentication", async () => {
      const { status } = await apiRequest("/api/orders", {
        method: "POST",
        body: JSON.stringify({ total: 10 }),
      });

      expect(status).toBe(401);
    });
  });

  describe("GET /api/orders/:id", () => {
    let orderId: string;

    beforeAll(async () => {
      await apiRequest("/api/cart/add", {
        method: "POST",
        headers: authHeaders(aliceToken),
        body: JSON.stringify({ productId, quantity: 1 }),
      });

      const { data: cart } = await apiRequest<CartResponse>("/api/cart", {
        headers: authHeaders(aliceToken),
      });

      const { data } = await apiRequest<OrderResponse>("/api/orders", {
        method: "POST",
        headers: authHeaders(aliceToken),
        body: JSON.stringify({ total: cart.total }),
      });

      orderId = data.id;
    });

    it("returns order details for the owner", async () => {
      const { status, data } = await apiRequest<OrderDetailResponse>(
        `/api/orders/${orderId}`,
        { headers: authHeaders(aliceToken) }
      );

      expect(status).toBe(200);
      expect(data.id).toBe(orderId);
      expect(data.status).toBe("PENDING");
      expect(data.customerEmail).toBe(TEST_USERS.alice.email);
      expect(data.deliveryAddress).toBeDefined();
      expect(data.deliveryAddress.street).toBeDefined();
      expect(data.deliveryAddress.city).toBeDefined();
    });

    it("returns 404 for non-existent order", async () => {
      const { status } = await apiRequest("/api/orders/ORD-999999", {
        headers: authHeaders(aliceToken),
      });

      expect(status).toBe(404);
    });

    it("requires authentication", async () => {
      const { status } = await apiRequest(`/api/orders/${orderId}`);
      expect(status).toBe(401);
    });
  });

  describe("GET /api/orders (admin)", () => {
    it("admin can list all orders", async () => {
      const adminToken = await loginOrFail(
        TEST_USERS.admin.email,
        TEST_USERS.admin.password
      );

      const { status, data } = await apiRequest<
        { id: string; total: number; status: string }[]
      >("/api/orders", {
        headers: authHeaders(adminToken),
      });

      expect(status).toBe(200);
      expect(Array.isArray(data)).toBe(true);
      expect(data.length).toBeGreaterThan(0);
    });

    it("non-admin cannot list all orders", async () => {
      const { status } = await apiRequest("/api/orders", {
        headers: authHeaders(aliceToken),
      });

      expect(status).toBe(403);
    });
  });
});
