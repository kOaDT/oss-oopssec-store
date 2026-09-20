import fs from "fs";
import path from "path";
import { prisma } from "./prisma";
import { parseSchema } from "./prisma-schema";
import { CANARY_SLUGS } from "./sql-injection-canary";

const SCHEMA_PATH = path.join(process.cwd(), "prisma", "schema.prisma");

const INIT_COMMANDS = [
  "  npm run setup                 (local clone)",
  "  docker compose up -d --build  (Docker, the entrypoint initializes on first start)",
];

const UPGRADE_COMMANDS = [
  "  npm run db:upgrade            (local clone)",
  "  docker compose up -d --build  (Docker, the entrypoint upgrades on start)",
];

const outOfDate = (drift: string): Error =>
  new Error(
    [
      `Database schema is out of date: ${drift}.`,
      "",
      "Catch it up, your progress is kept:",
      ...UPGRADE_COMMANDS,
      "",
    ].join("\n")
  );

/**
 * An upgrade that only pulls new code leaves the database a schema behind, and a
 * query against a table or column added since then throws on pages the player
 * never associates with the database. Refuse to serve rather than 500 on every
 * view.
 */
export const assertDatabaseIsCurrent = async (): Promise<void> => {
  const expected = parseSchema(fs.readFileSync(SCHEMA_PATH, "utf-8"));

  const rows = await prisma.$queryRaw<{ table: string; column: string }[]>`
    SELECT m.name AS "table", p.name AS "column"
    FROM sqlite_master m JOIN pragma_table_info(m.name) p
    WHERE m.type = 'table'
  `;

  const live = new Map<string, Set<string>>();
  for (const row of rows) {
    const columns = live.get(row.table) ?? new Set<string>();
    columns.add(row.column);
    live.set(row.table, columns);
  }

  const missingTables = expected.filter((entry) => !live.has(entry.table));

  if (missingTables.length === expected.length) {
    throw new Error(
      [
        `Database not initialized: none of the ${expected.length} tables declared in prisma/schema.prisma exist.`,
        "",
        "Create and seed it:",
        ...INIT_COMMANDS,
        "",
      ].join("\n")
    );
  }

  if (missingTables.length > 0) {
    throw outOfDate(
      `prisma/schema.prisma declares tables this database does not have (${missingTables
        .map((entry) => entry.table)
        .join(", ")})`
    );
  }

  // A release far more often adds a column than a table, and the table check
  // alone lets that database through to fail on `no such column` per request.
  const missingColumns = expected.flatMap((entry) => {
    const columns = live.get(entry.table)!;
    return entry.columns
      .filter((column) => !columns.has(column))
      .map((column) => `${entry.table}.${column}`);
  });

  if (missingColumns.length > 0) {
    throw outOfDate(
      `prisma/schema.prisma declares columns this database does not have (${missingColumns.join(", ")})`
    );
  }

  const canaries = await prisma.internalSecret.count({
    where: { slug: { in: [...CANARY_SLUGS] } },
  });

  // A warning rather than a throw: a lab missing its canaries still serves
  // every other challenge, so refusing to boot costs more than it saves.
  if (canaries < CANARY_SLUGS.length) {
    console.warn(
      `${CANARY_SLUGS.length - canaries} of the ${CANARY_SLUGS.length} SQL injection canaries are missing, so their flags cannot be claimed. Run \`npm run db:upgrade\` to mint them.`
    );
  }
};
