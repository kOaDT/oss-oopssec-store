import { readFileSync } from "fs";
import { join } from "path";
import { parseSchema } from "../../lib/prisma-schema";

const SCHEMA = readFileSync(
  join(__dirname, "..", "..", "prisma", "schema.prisma"),
  "utf-8"
);

const columnsOf = (table: string) =>
  parseSchema(SCHEMA).find((entry) => entry.table === table)?.columns ?? [];

describe("parseSchema", () => {
  it("resolves the mapped name, which is what the startup guard looks up", () => {
    const tables = parseSchema(SCHEMA).map((entry) => entry.table);

    expect(tables).toContain("internal_secrets");
    expect(tables).not.toContain("InternalSecret");
  });

  it("gives every table of the live schema at least its primary key", () => {
    for (const entry of parseSchema(SCHEMA)) {
      expect(entry.columns).toContain("id");
    }
  });

  it("keeps the foreign key of a relation but not the relation field itself", () => {
    const users = columnsOf("users");

    expect(users).toContain("addressId");
    expect(users).not.toContain("address");
  });

  it("ignores the many side of a relation, which has no column", () => {
    expect(columnsOf("users")).not.toContain("orders");
  });

  it("keeps an enum field, which is stored as a column", () => {
    expect(columnsOf("users")).toContain("role");
  });

  it("falls back to the model name when the model has no @@map", () => {
    const schema = ["model Unmapped {", "  id String @id", "}"].join("\n");

    expect(parseSchema(schema)).toEqual([
      { table: "Unmapped", columns: ["id"] },
    ]);
  });

  it("accepts the named form of @@map and of a field @map", () => {
    const schema = [
      "model Renamed {",
      "  id       String @id",
      '  lastName String @map(name: "last_name")',
      "",
      '  @@map(name: "renamed_rows")',
      "}",
    ].join("\n");

    expect(parseSchema(schema)).toEqual([
      { table: "renamed_rows", columns: ["id", "last_name"] },
    ]);
  });

  it("does not mistake a relation index for a column", () => {
    const schema = [
      "model Post {",
      "  id       String @id",
      "  authorId String",
      "  author   Author @relation(fields: [authorId], references: [id])",
      "",
      "  @@index([authorId])",
      "}",
      "",
      "model Author {",
      "  id    String @id",
      "  posts Post[]",
      "}",
    ].join("\n");

    expect(parseSchema(schema)).toEqual([
      { table: "Post", columns: ["id", "authorId"] },
      { table: "Author", columns: ["id"] },
    ]);
  });
});
