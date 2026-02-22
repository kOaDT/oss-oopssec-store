import {
  apiRequest,
  loginOrFail,
  authHeaders,
  TEST_USERS,
  expectFlag,
} from "../helpers/api";
import { FLAGS } from "../helpers/flags";

describe("SQL Injection - Order Search", () => {
  let token: string;

  beforeAll(async () => {
    token = await loginOrFail(
      TEST_USERS.alice.email,
      TEST_USERS.alice.password
    );
  });

  it("should return the flag when a SQL injection is detected", async () => {
    const { status, data } = await apiRequest("/api/orders/search", {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ status: "PENDING' OR '1'='1" }),
    });

    expect(status).toBe(200);
    expectFlag(data, FLAGS.SQL_INJECTION);
    expect(data).toHaveProperty("message", "SQL injection detected");
  });

  it("should block access to the flags table", async () => {
    const { status, data } = await apiRequest("/api/orders/search", {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({
        status: "PENDING' UNION SELECT flag FROM flags --",
      }),
    });

    expect(status).toBe(403);
    expect((data as { error: string }).error).toContain(
      "Access to flags table is not allowed"
    );
  });

  it("should not return a flag for a normal status filter", async () => {
    const { status, data } = await apiRequest("/api/orders/search", {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ status: "PENDING" }),
    });

    expect(status).toBe(200);
    expect(data).not.toHaveProperty("flag");
  });

  it("should reject unauthenticated requests", async () => {
    const { status } = await apiRequest("/api/orders/search", {
      method: "POST",
      body: JSON.stringify({ status: "PENDING" }),
    });

    expect(status).toBe(401);
  });
});
