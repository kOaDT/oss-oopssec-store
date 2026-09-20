export interface SchemaTable {
  table: string;
  columns: string[];
}

const MODEL = /^model\s+(\w+)\s*\{/;
const MAP = /@@?map\(\s*(?:name:\s*)?"([^"]+)"\)/;
const FIELD = /^\s+(\w+)\s+(\w+)(\[\])?/;

/**
 * The `prisma-client` generator exposes no runtime datamodel, so the schema file
 * stays the source of truth for the tables and columns an install is expected to
 * have. Relation fields are skipped: they carry no column of their own, the
 * scalar next to them does.
 */
export const parseSchema = (schema: string): SchemaTable[] => {
  const lines = schema.split("\n");
  const models = new Set(lines.flatMap((line) => line.match(MODEL)?.[1] ?? []));

  const tables: SchemaTable[] = [];
  let current: SchemaTable | null = null;

  for (const line of lines) {
    const declaration = line.match(MODEL);
    if (declaration) {
      current = { table: declaration[1], columns: [] };
      continue;
    }

    if (current === null) continue;

    if (line.startsWith("}")) {
      tables.push(current);
      current = null;
      continue;
    }

    if (line.trimStart().startsWith("@@")) {
      const mapped = line.match(MAP);
      if (mapped) current.table = mapped[1];
      continue;
    }

    const field = line.match(FIELD);
    if (!field) continue;

    const [, name, type, list] = field;
    // SQLite has no scalar lists, so `[]` is always the many side of a relation.
    if (list || models.has(type)) continue;

    current.columns.push(line.match(MAP)?.[1] ?? name);
  }

  return tables;
};
