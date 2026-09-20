import { seedCanaries } from "../../prisma/challenge-data";
import { CANARY_SLUGS } from "../../lib/sql-injection-canary";
import type { PrismaClient } from "../../lib/generated/prisma/client";

interface CanaryRow {
  slug: string;
  token: string;
}

/**
 * Stands in for the `internal_secrets` table so the upsert can be observed as
 * the rows it leaves behind, which is what an upgrade has to get right.
 */
const fakeDatabase = (rows: CanaryRow[]) => {
  let state = [...rows];

  const client = {
    internalSecret: {
      deleteMany: async ({
        where,
      }: {
        where: { slug: { notIn: string[] } };
      }) => {
        state = state.filter((row) => where.slug.notIn.includes(row.slug));
      },
      upsert: async ({
        where,
        update,
        create,
      }: {
        where: { slug: string };
        update: Partial<CanaryRow>;
        create: CanaryRow;
      }) => {
        const existing = state.find((row) => row.slug === where.slug);
        // `update` has to be applied, or a token rotation would go unnoticed.
        if (existing) Object.assign(existing, update);
        else state.push(create);
      },
    },
  };

  return {
    client: client as unknown as PrismaClient,
    rows: () => state,
  };
};

describe("seedCanaries", () => {
  const [firstSlug] = CANARY_SLUGS;

  let log: jest.SpyInstance;

  beforeAll(() => {
    log = jest.spyOn(console, "log").mockImplementation(() => {});
  });

  afterAll(() => {
    log.mockRestore();
  });

  it("keeps the token of a canary already planted", async () => {
    const db = fakeDatabase([{ slug: firstSlug, token: "CANARY-KEEP-ME" }]);

    await seedCanaries(db.client);

    expect(db.rows()).toContainEqual({
      slug: firstSlug,
      token: "CANARY-KEEP-ME",
    });
  });

  it("plants every canary an upgraded database is missing", async () => {
    const db = fakeDatabase([{ slug: firstSlug, token: "CANARY-KEEP-ME" }]);

    await seedCanaries(db.client);

    expect(
      db
        .rows()
        .map((row) => row.slug)
        .sort()
    ).toEqual([...CANARY_SLUGS].sort());
  });

  it("drops a canary whose challenge no longer exists", async () => {
    const db = fakeDatabase([
      { slug: "retired-injection", token: "CANARY-OLD" },
    ]);

    await seedCanaries(db.client);

    expect(db.rows().map((row) => row.slug)).not.toContain("retired-injection");
  });
});
