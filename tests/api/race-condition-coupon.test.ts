import {
  apiRequest,
  loginOrFail,
  authHeaders,
  TEST_USERS,
  getFirstProductId,
} from "../helpers/api";
import { FLAGS } from "../helpers/flags";
import Database from "better-sqlite3";
import { getDatabaseUrl } from "@/lib/database";

const COUPON_CODE = "FLASHSALE";

async function addProductToCart(token: string): Promise<number> {
  const productId = await getFirstProductId();
  await apiRequest("/api/cart/add", {
    method: "POST",
    headers: authHeaders(token),
    body: JSON.stringify({ productId, quantity: 1 }),
  });
  const { data } = await apiRequest<{ total: number }>("/api/cart", {
    headers: authHeaders(token),
  });
  return (data as { total: number }).total;
}

describe("Race Condition - Coupon Abuse (API)", () => {
  let token: string;

  beforeAll(async () => {
    token = await loginOrFail(
      TEST_USERS.alice.email,
      TEST_USERS.alice.password
    );
  });

  beforeEach(() => {
    const dbPath = getDatabaseUrl().replace(/^file:/, "");
    const db = new Database(dbPath);
    db.prepare(`UPDATE coupons SET usedCount = 0 WHERE code = ?`).run(
      COUPON_CODE
    );
    db.close();
  });

  it("preview endpoint returns the discounted total without consuming the coupon", async () => {
    const { status, data } = await apiRequest<{
      discountedTotal: number;
      discountPercent: number;
    }>("/api/coupon/apply", {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ code: COUPON_CODE, cartTotal: 100 }),
    });

    expect(status).toBe(200);
    expect(data).toHaveProperty("discountPercent", 50);
    expect((data as { discountedTotal: number }).discountedTotal).toBe(50);

    // Calling it again should still succeed — the coupon was not consumed
    const { status: status2 } = await apiRequest("/api/coupon/apply", {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ code: COUPON_CODE, cartTotal: 100 }),
    });
    expect(status2).toBe(200);
  });

  it("preview endpoint returns 404 for an unknown coupon", async () => {
    const { status } = await apiRequest("/api/coupon/apply", {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ code: "DOESNOTEXIST", cartTotal: 100 }),
    });

    expect(status).toBe(404);
  });

  it("placing an order with a coupon applies the discount and consumes the coupon", async () => {
    const cartTotal = await addProductToCart(token);
    const expectedDiscounted = cartTotal * 0.5;

    const { status, data } = await apiRequest<{
      id: string;
      total: number;
      flag?: string;
    }>("/api/orders", {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({
        total: expectedDiscounted,
        couponCode: COUPON_CODE,
      }),
    });

    expect(status).toBe(200);
    expect((data as { total: number }).total).toBeCloseTo(
      expectedDiscounted,
      2
    );

    // Second order with same coupon should return 400 from the coupon check
    // (coupon is now consumed — usedCount >= maxUses)
    const cartTotal2 = await addProductToCart(token);
    const { status: status2 } = await apiRequest("/api/orders", {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({
        total: cartTotal2 * 0.5,
        couponCode: COUPON_CODE,
      }),
    });

    // Order still succeeds (coupon is silently skipped), but no discount
    expect(status2).toBe(200);
  });

  it("concurrent orders with the same coupon result in at least one containing the flag", async () => {
    await addProductToCart(token);
    const { data: cartData } = await apiRequest<{ total: number }>(
      "/api/cart",
      {
        headers: authHeaders(token),
      }
    );
    const cartTotal = (cartData as { total: number }).total;
    const discountedTotal = cartTotal * 0.5;

    const concurrency = 30;
    const requests = Array.from({ length: concurrency }, () =>
      apiRequest<{
        id?: string;
        total?: number;
        flag?: string;
        error?: string;
      }>("/api/orders", {
        method: "POST",
        headers: authHeaders(token),
        body: JSON.stringify({
          total: discountedTotal,
          couponCode: COUPON_CODE,
        }),
      })
    );

    const results = await Promise.all(requests);
    const successes = results.filter((r) => r.status === 200);
    const withFlag = successes.filter(
      (r) =>
        (r.data as { flag?: string }).flag === FLAGS.RACE_CONDITION_COUPON_ABUSE
    );

    expect(successes.length).toBeGreaterThanOrEqual(2);
    expect(withFlag.length).toBeGreaterThanOrEqual(1);
  });

  it("requires authentication", async () => {
    const { status } = await apiRequest("/api/coupon/apply", {
      method: "POST",
      body: JSON.stringify({ code: COUPON_CODE, cartTotal: 100 }),
    });

    expect(status).toBe(401);
  });
});
