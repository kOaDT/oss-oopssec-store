import { apiRequest, expectFlag } from "../helpers/api";

const FLAG = "OSS{x_f0rw4rd3d_f0r_sql1}";

describe("SQL Injection - X-Forwarded-For", () => {
  it("should return the flag when SQL injection is detected in X-Forwarded-For", async () => {
    const { status, data } = await apiRequest("/api/tracking", {
      method: "POST",
      body: JSON.stringify({ path: "/", sessionId: "test" }),
      headers: { "X-Forwarded-For": "127.0.0.1' OR '1'='1" },
    });

    expect(status).toBe(200);
    expectFlag(data, FLAG);
    expect((data as { message: string }).message).toContain(
      "SQL injection detected"
    );
  });

  it("should block access to the flags table via header", async () => {
    const { status, data } = await apiRequest("/api/tracking", {
      method: "POST",
      body: JSON.stringify({ path: "/", sessionId: "test" }),
      headers: {
        "X-Forwarded-For": "127.0.0.1' UNION SELECT flag FROM flags --",
      },
    });

    expect(status).toBe(403);
    expect((data as { error: string }).error).toContain(
      "Access to flags table is not allowed"
    );
  });

  it("should handle normal tracking request without returning a flag", async () => {
    const { status, data } = await apiRequest("/api/tracking", {
      method: "POST",
      body: JSON.stringify({ path: "/products", sessionId: "abc" }),
    });

    expect(status).toBe(200);
    expect(data).toHaveProperty("success", true);
    expect(data).not.toHaveProperty("flag");
  });

  it("should return the flag when UNION keyword is in X-Forwarded-For", async () => {
    const { status, data } = await apiRequest("/api/tracking", {
      method: "POST",
      body: JSON.stringify({ path: "/", sessionId: "test" }),
      headers: { "X-Forwarded-For": "1' UNION SELECT 1 --" },
    });

    expect(status).toBe(200);
    expect(data).toHaveProperty("flag");
  });
});
