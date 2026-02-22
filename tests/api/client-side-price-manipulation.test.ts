import {
  apiRequest,
  loginOrFail,
  authHeaders,
  TEST_USERS,
  expectFlag,
  getFirstProductId,
} from "../helpers/api";
import { FLAGS } from "../helpers/flags";

describe("Client-Side Price Manipulation (API)", () => {
  it("order with manipulated price returns flag", async () => {
    const token = await loginOrFail(
      TEST_USERS.alice.email,
      TEST_USERS.alice.password
    );

    const productId = await getFirstProductId();
    await apiRequest("/api/cart/add", {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ productId, quantity: 1 }),
    });

    const { status, data } = await apiRequest<{
      id: string;
      total: number;
      status: string;
      flag?: string;
    }>("/api/orders", {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ total: 0.01 }),
    });

    expect(status).toBe(200);
    expectFlag(data, FLAGS.CLIENT_SIDE_PRICE_MANIPULATION);
    expect(data).toHaveProperty("total", 0.01);
  });

  it("order with correct price does NOT return flag", async () => {
    const token = await loginOrFail(
      TEST_USERS.alice.email,
      TEST_USERS.alice.password
    );

    const productId = await getFirstProductId();
    await apiRequest("/api/cart/add", {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ productId, quantity: 1 }),
    });

    const { status: cartStatus, data: cartData } = await apiRequest<{
      cartItems: unknown[];
      total: number;
    }>("/api/cart", {
      headers: authHeaders(token),
    });
    expect(cartStatus).toBe(200);
    const correctTotal = (cartData as { total: number }).total;

    const { status, data } = await apiRequest<{
      id: string;
      total: number;
      status: string;
      flag?: string;
    }>("/api/orders", {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ total: correctTotal }),
    });

    expect(status).toBe(200);
    expect(data).not.toHaveProperty("flag");
  });

  it("order with zero or negative total is rejected", async () => {
    const token = await loginOrFail(
      TEST_USERS.alice.email,
      TEST_USERS.alice.password
    );

    const { status } = await apiRequest("/api/orders", {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ total: 0 }),
    });

    expect(status).toBe(400);
  });

  it("order with empty cart is rejected", async () => {
    const token = await loginOrFail(
      TEST_USERS.bob.email,
      TEST_USERS.bob.password
    );

    const { status, data } = await apiRequest<{ error?: string }>(
      "/api/orders",
      {
        method: "POST",
        headers: authHeaders(token),
        body: JSON.stringify({ total: 10 }),
      }
    );

    expect(status).toBe(400);
    expect(data).toHaveProperty("error");
    expect((data as { error: string }).error).toMatch(/Cart is empty/i);
  });
});
