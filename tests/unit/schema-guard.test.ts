import { readFileSync } from "fs";
import { join } from "path";
import { parseSchema } from "../../lib/prisma-schema";
import { CANARY_SLUGS } from "../../lib/sql-injection-canary";

const queryRaw = jest.fn();
const count = jest.fn();
const findFirst = jest.fn();

jest.mock("../../lib/prisma", () => ({
  prisma: {
    $queryRaw: (...args: unknown[]) => queryRaw(...args),
    internalSecret: { count: (...args: unknown[]) => count(...args) },
    projectInit: { findFirst: (...args: unknown[]) => findFirst(...args) },
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

const serves = (
  rows: { table: string; column: string }[],
  state: { canaries?: number; seeded?: boolean } = {}
) => {
  queryRaw.mockResolvedValue(rows);
  count.mockResolvedValue(state.canaries ?? CANARY_SLUGS.length);
  findFirst.mockResolvedValue(state.seeded === false ? null : { id: "init" });
};

describe("assertDatabaseIsCurrent", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("serves a database that matches the schema", async () => {
    serves(upToDate());

    await expect(assertDatabaseIsCurrent()).resolves.toBeUndefined();
  });

  it("serves a database holding tables and columns the schema never declared", async () => {
    // SQLite creates `sqlite_sequence` on its own, so a guard that refused
    // anything unexpected would refuse every real database.
    serves([
      ...upToDate(),
      { table: "sqlite_sequence", column: "name" },
      { table: "sqlite_sequence", column: "seq" },
      { table: "users", column: "column_from_a_later_release" },
    ]);

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

  it("refuses a schema-complete database that was never seeded", async () => {
    serves(upToDate(), { seeded: false });

    await expect(assertDatabaseIsCurrent()).rejects.toThrow(
      /not initialized[\s\S]*project_init[\s\S]*npm run setup/
    );
  });

  it("keeps serving when canaries are missing, so the other flags stay playable", async () => {
    const warn = jest.spyOn(console, "warn").mockImplementation(() => {});
    serves(upToDate(), { canaries: CANARY_SLUGS.length - 1 });

    await expect(assertDatabaseIsCurrent()).resolves.toBeUndefined();
    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining(
        `1 of the ${CANARY_SLUGS.length} SQL injection canaries are missing`
      )
    );

    warn.mockRestore();
  });
});
