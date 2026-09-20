import { seedCanaries, seedChallengeData } from "../../prisma/challenge-data";
import { flags, flagHints } from "../../prisma/flags";
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

interface FlagRow {
  id: string;
  slug: string;
  flag: string;
}

interface HintRow {
  id: string;
  flagId: string;
  level: number;
  content: string;
}

/**
 * Stands in for `flags` and `hints`, the two tables `found_flags` and
 * `revealed_hints` point at: an upgrade that recreated either row instead of
 * updating it would drop the progress hanging off the old id.
 */
const fakeChallengeDatabase = (flagRows: FlagRow[], hintRows: HintRow[]) => {
  let minted = 0;

  const client = {
    flag: {
      upsert: async ({
        where,
        update,
        create,
      }: {
        where: { slug: string };
        update: Partial<FlagRow>;
        create: Omit<FlagRow, "id">;
      }) => {
        const existing = flagRows.find((row) => row.slug === where.slug);
        if (existing) Object.assign(existing, update);
        else flagRows.push({ id: `minted-${++minted}`, ...create });
      },
      findUnique: async ({ where }: { where: { slug: string } }) =>
        flagRows.find((row) => row.slug === where.slug) ?? null,
    },
    hint: {
      upsert: async ({
        where,
        update,
        create,
      }: {
        where: { flagId_level: { flagId: string; level: number } };
        update: Partial<HintRow>;
        create: Omit<HintRow, "id">;
      }) => {
        const { flagId, level } = where.flagId_level;
        const existing = hintRows.find(
          (row) => row.flagId === flagId && row.level === level
        );
        if (existing) Object.assign(existing, update);
        else hintRows.push({ id: `minted-${++minted}`, ...create });
      },
    },
    internalSecret: {
      deleteMany: async () => {},
      upsert: async () => {},
    },
  };

  return client as unknown as PrismaClient;
};

describe("seedChallengeData", () => {
  const [firstFlag] = flags;

  let log: jest.SpyInstance;

  beforeAll(() => {
    log = jest.spyOn(console, "log").mockImplementation(() => {});
  });

  afterAll(() => {
    log.mockRestore();
  });

  it("refreshes a flag a player already captured without changing its id", async () => {
    const flagRows: FlagRow[] = [
      { id: "captured", slug: firstFlag.slug, flag: "OSS{stale_value}" },
    ];

    await seedChallengeData(fakeChallengeDatabase(flagRows, []));

    expect(flagRows).toContainEqual(
      expect.objectContaining({ id: "captured", flag: firstFlag.flag })
    );
  });

  it("refreshes a hint a player already revealed without changing its id", async () => {
    const flagRows: FlagRow[] = [
      { id: "captured", slug: firstFlag.slug, flag: firstFlag.flag },
    ];
    const hintRows: HintRow[] = [
      { id: "revealed", flagId: "captured", level: 1, content: "stale hint" },
    ];

    await seedChallengeData(fakeChallengeDatabase(flagRows, hintRows));

    expect(
      hintRows.filter((row) => row.flagId === "captured" && row.level === 1)
    ).toEqual([
      {
        id: "revealed",
        flagId: "captured",
        level: 1,
        content: flagHints[firstFlag.slug][0],
      },
    ]);
  });
});
