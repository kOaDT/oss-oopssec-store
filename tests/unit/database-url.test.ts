import path from "path";

describe("getDatabaseUrl", () => {
  const originalEnv = process.env.DATABASE_URL;

  afterEach(() => {
    if (originalEnv !== undefined) {
      process.env.DATABASE_URL = originalEnv;
    } else {
      delete process.env.DATABASE_URL;
    }
    jest.resetModules();
  });

  async function loadGetDatabaseUrl() {
    const mod = await import("../../lib/database");
    return mod.getDatabaseUrl;
  }

  it("returns default path when DATABASE_URL is not set", async () => {
    delete process.env.DATABASE_URL;
    const getDatabaseUrl = await loadGetDatabaseUrl();

    const result = getDatabaseUrl();
    const expectedPath = path.resolve(process.cwd(), "prisma", "dev.db");

    expect(result).toBe(`file:${expectedPath}`);
  });

  it("resolves relative file:./  paths to absolute", async () => {
    process.env.DATABASE_URL = "file:./prisma/test.db";
    const getDatabaseUrl = await loadGetDatabaseUrl();

    const result = getDatabaseUrl();
    const expectedPath = path.resolve(process.cwd(), "prisma/test.db");

    expect(result).toBe(`file:${expectedPath}`);
  });

  it("keeps absolute file: paths unchanged", async () => {
    process.env.DATABASE_URL = "file:/absolute/path/to/db.sqlite";
    const getDatabaseUrl = await loadGetDatabaseUrl();

    const result = getDatabaseUrl();

    expect(result).toBe("file:/absolute/path/to/db.sqlite");
  });

  it("strips surrounding quotes from DATABASE_URL", async () => {
    process.env.DATABASE_URL = '"file:/some/path/db.sqlite"';
    const getDatabaseUrl = await loadGetDatabaseUrl();

    const result = getDatabaseUrl();

    expect(result).toBe("file:/some/path/db.sqlite");
  });
});
