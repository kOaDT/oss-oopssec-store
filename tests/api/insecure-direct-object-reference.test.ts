import {
  apiRequest,
  loginOrFail,
  authHeaders,
  TEST_USERS,
  expectFlag,
} from "../helpers/api";
import { FLAGS } from "../helpers/flags";

describe("Insecure Direct Object Reference (IDOR)", () => {
  it("accessing another user's order returns flag", async () => {
    const aliceToken = await loginOrFail(
      TEST_USERS.alice.email,
      TEST_USERS.alice.password
    );

    const { status, data } = await apiRequest<{
      id: string;
      total: number;
      status: string;
      customerEmail: string;
      flag?: string;
    }>("/api/orders/ORD-001", {
      headers: authHeaders(aliceToken),
    });

    expect(status).toBe(200);
    expectFlag(data, FLAGS.INSECURE_DIRECT_OBJECT_REFERENCE);
    expect(data).toHaveProperty("id", "ORD-001");
    expect(data).toHaveProperty("total");
    expect(data).toHaveProperty("status");
    expect(data).toHaveProperty("customerEmail");
  });

  it("accessing own order does NOT return flag", async () => {
    const bobToken = await loginOrFail(
      TEST_USERS.bob.email,
      TEST_USERS.bob.password
    );

    const { status, data } = await apiRequest<{ flag?: string }>(
      "/api/orders/ORD-001",
      { headers: authHeaders(bobToken) }
    );

    expect(status).toBe(200);
    expect(data).not.toHaveProperty("flag");
  });

  it("non-existent order returns 404", async () => {
    const aliceToken = await loginOrFail(
      TEST_USERS.alice.email,
      TEST_USERS.alice.password
    );

    const { status } = await apiRequest("/api/orders/ORD-999", {
      headers: authHeaders(aliceToken),
    });

    expect(status).toBe(404);
  });

  it("unauthenticated request is rejected", async () => {
    const { status } = await apiRequest("/api/orders/ORD-001");
    expect(status).toBe(401);
  });
});
