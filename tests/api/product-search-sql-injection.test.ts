import { apiRequest, expectFlag } from "../helpers/api";

const FLAG = "OSS{pr0duct_s34rch_sql_1nj3ct10n}";

describe("SQL Injection - Product Search", () => {
  it("should return the flag when a SQL injection is detected", async () => {
    const { status, data } = await apiRequest(
      `/api/products/search?q=${encodeURIComponent("' UNION SELECT 1,2,3,4,5 --")}`
    );

    expect(status).toBe(200);
    expectFlag(data, FLAG);
    expect(data).toHaveProperty("message", "SQL injection detected");
  });

  it("should block access to the flags table", async () => {
    const { status, data } = await apiRequest(
      `/api/products/search?q=${encodeURIComponent("' UNION SELECT flag FROM flags --")}`
    );

    expect(status).toBe(403);
    expect((data as { error: string }).error).toContain(
      "Access to flags table is not allowed"
    );
  });

  it("should not return a flag for a normal search", async () => {
    const { status, data } = await apiRequest("/api/products/search?q=bread");

    expect(status).toBe(200);
    expect(data).toHaveProperty("products");
    expect(Array.isArray((data as { products: unknown[] }).products)).toBe(
      true
    );
    expect(data).not.toHaveProperty("flag");
  });

  it("should return empty results for an empty query", async () => {
    const { status, data } = await apiRequest("/api/products/search?q=");

    expect(status).toBe(200);
    expect((data as { products: unknown[] }).products).toEqual([]);
  });
});
