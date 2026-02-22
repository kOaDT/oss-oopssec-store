import {
  apiRequest,
  loginOrFail,
  authHeaders,
  TEST_USERS,
  expectFlag,
} from "../helpers/api";
import { FLAGS } from "../helpers/flags";
const SQL_PAYLOAD = "test' UNION SELECT 1,2,3,4,5,6 --";

describe("Second-Order SQL Injection", () => {
  it("should store SQL payload as review author and return flag when admin filters by author", async () => {
    const productsRes = await apiRequest<{ id: number }[]>("/api/products");
    expect(productsRes.status).toBe(200);
    const products = Array.isArray(productsRes.data) ? productsRes.data : [];
    const productId = products[0]?.id;
    expect(productId).toBeDefined();

    const userToken = await loginOrFail(
      TEST_USERS.alice.email,
      TEST_USERS.alice.password
    );

    const createRes = await apiRequest(`/api/products/${productId}/reviews`, {
      method: "POST",
      headers: authHeaders(userToken),
      body: JSON.stringify({
        content: "Great product!",
        author: SQL_PAYLOAD,
      }),
    });
    expect(createRes.status).toBe(201);

    const adminToken = await loginOrFail(
      TEST_USERS.admin.email,
      TEST_USERS.admin.password
    );

    const adminRes = await apiRequest(
      `/api/admin/reviews?author=${encodeURIComponent(SQL_PAYLOAD)}`,
      { headers: authHeaders(adminToken) }
    );
    expect(adminRes.status).toBe(200);
    expectFlag(adminRes.data, FLAGS.SECOND_ORDER_SQL_INJECTION);
    expect((adminRes.data as { message?: string }).message).toMatch(
      /SQL injection detected/
    );
  });

  it("should return 403 when admin tries to access flags table via author filter", async () => {
    const adminToken = await loginOrFail(
      TEST_USERS.admin.email,
      TEST_USERS.admin.password
    );

    const adminRes = await apiRequest(
      `/api/admin/reviews?author=${encodeURIComponent(
        "test' UNION SELECT flag FROM flags --"
      )}`,
      { headers: authHeaders(adminToken) }
    );
    expect(adminRes.status).toBe(403);
    expect((adminRes.data as { error: string }).error).toContain(
      "Access to flags table is not allowed"
    );
  });

  it("should return 200 for normal author filter without flag", async () => {
    const adminToken = await loginOrFail(
      TEST_USERS.admin.email,
      TEST_USERS.admin.password
    );

    const { status, data } = await apiRequest(
      "/api/admin/reviews?author=alice@example.com",
      { headers: authHeaders(adminToken) }
    );
    expect(status).toBe(200);
    expect(data).not.toHaveProperty("flag");
  });

  it("should return 403 when non-admin accesses admin reviews", async () => {
    const userToken = await loginOrFail(
      TEST_USERS.alice.email,
      TEST_USERS.alice.password
    );

    const { status } = await apiRequest("/api/admin/reviews", {
      headers: authHeaders(userToken),
    });
    expect(status).toBe(403);
  });
});
