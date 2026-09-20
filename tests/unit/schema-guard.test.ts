import { readFileSync } from "fs";
import { join } from "path";
import { parseSchema } from "../../lib/prisma-schema";
import { CANARY_SLUGS } from "../../lib/sql-injection-canary";

const queryRaw = jest.fn();
const count = jest.fn();

jest.mock("../../lib/prisma", () => ({
  prisma: {
    $queryRaw: (...args: unknown[]) => queryRaw(...args),
    internalSecret: { count: (...args: unknown[]) => count(...args) },
  },
}));

import { assertDatabaseIsCurrent } from "../../lib/schema-guard";

const SCHEMA = parseSchema(
  readFileSync(join(__dirname, "..", "..", "prisma", "schema.prisma"), "utf-8")
);

/** Every table and column the live schema declares, as the guard reads them back. */
const upToDate = () =>
  SCHEMA.flatMap((entry) =>
    entry.columns.map((column) => ({ table: entry.table, column }))
  );

const serves = (rows: { table: string; column: string }[]) => {
  queryRaw.mockResolvedValue(rows);
  count.mockResolvedValue(CANARY_SLUGS.length);
};

describe("assertDatabaseIsCurrent", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("serves a database that matches the schema", async () => {
    serves(upToDate());

    await expect(assertDatabaseIsCurrent()).resolves.toBeUndefined();
  });

  it("tells an empty database to be created, not upgraded", async () => {
    serves([]);

    await expect(assertDatabaseIsCurrent()).rejects.toThrow(
      /not initialized[\s\S]*npm run setup/
    );
  });

  it("names the missing table and the upgrade command", async () => {
    serves(upToDate().filter((row) => row.table !== "internal_secrets"));

    await expect(assertDatabaseIsCurrent()).rejects.toThrow(
      /out of date[\s\S]*internal_secrets[\s\S]*npm run db:upgrade/
    );
  });

  it("refuses a table that is missing a single column", async () => {
    serves(
      upToDate().filter(
        (row) => !(row.table === "internal_secrets" && row.column === "token")
      )
    );

    await expect(assertDatabaseIsCurrent()).rejects.toThrow(
      /out of date[\s\S]*internal_secrets\.token[\s\S]*npm run db:upgrade/
    );
  });

  it("keeps serving when canaries are missing, so the other flags stay playable", async () => {
    const warn = jest.spyOn(console, "warn").mockImplementation(() => {});
    queryRaw.mockResolvedValue(upToDate());
    count.mockResolvedValue(CANARY_SLUGS.length - 1);

    await expect(assertDatabaseIsCurrent()).resolves.toBeUndefined();
    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining(
        `1 of the ${CANARY_SLUGS.length} SQL injection canaries are missing`
      )
    );

    warn.mockRestore();
  });
});
