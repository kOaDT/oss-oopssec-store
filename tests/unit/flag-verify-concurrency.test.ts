/**
 * Two submissions of the same correct flag can both pass the "already found?"
 * lookup before either inserts. The unique index on `found_flags.flagId` then
 * rejects the second insert, and that request must still read as a correct
 * flag: the checker shows "Invalid flag" for any `valid: false`.
 */

const findFirst = jest.fn();
const findUnique = jest.fn();
const create = jest.fn();

jest.mock("../../lib/prisma", () => ({
  prisma: {
    flag: { findFirst: (...args: unknown[]) => findFirst(...args) },
    foundFlag: {
      findUnique: (...args: unknown[]) => findUnique(...args),
      create: (...args: unknown[]) => create(...args),
    },
  },
}));

jest.mock("../../lib/logger", () => ({
  logger: { error: jest.fn(), warn: jest.fn(), info: jest.fn() },
}));

import { POST } from "../../app/api/flags/verify/route";

const FLAG = {
  id: "flag-1",
  slug: "some-challenge",
  flag: "OSS{not_a_real_flag}",
};

const submit = (flag: string) =>
  POST(
    new Request("http://localhost/api/flags/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ flag }),
    })
  );

// The generated client cannot load under Jest, so this mirrors the shape of
// its PrismaClientKnownRequestError: the code is what the route can rely on.
const uniqueViolation = () =>
  Object.assign(
    new Error("Unique constraint failed on the fields: (`flagId`)"),
    { code: "P2002" }
  );

describe("POST /api/flags/verify with concurrent submissions", () => {
  beforeEach(() => {
    jest.resetAllMocks();
    findFirst.mockResolvedValue(FLAG);
  });

  it("reports the flag as already found when another request recorded it first", async () => {
    const foundAt = new Date("2026-11-22T01:20:00.000Z");
    findUnique
      .mockResolvedValueOnce(null)
      .mockResolvedValueOnce({ id: "found-1", flagId: FLAG.id, foundAt });
    create.mockRejectedValueOnce(uniqueViolation());

    const response = await submit(FLAG.flag);

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      valid: true,
      slug: FLAG.slug,
      alreadyFound: true,
      foundAt: foundAt.toISOString(),
    });
  });

  it("still answers 500 for any other database error", async () => {
    findUnique.mockResolvedValueOnce(null);
    create.mockRejectedValueOnce(new Error("database is locked"));

    const response = await submit(FLAG.flag);

    expect(response.status).toBe(500);
  });
});
