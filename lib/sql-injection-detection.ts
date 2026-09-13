const SQL_KEYWORDS = [
  "UNION",
  "SELECT",
  "INSERT",
  "UPDATE",
  "DELETE",
  "DROP",
  "CREATE",
  "ALTER",
  "EXEC",
  "EXECUTE",
  "SCRIPT",
  "OR 1=1",
  "OR '1'='1",
  'OR "1"="1',
  "';",
  '";',
  "--",
  "||",
  "/*",
  "*/",
  "XP_",
  "sp_",
];

export function isSQLInjectionAttempt(input: string): boolean {
  const upperInput = input.toUpperCase();
  return SQL_KEYWORDS.some((keyword) => upperInput.includes(keyword));
}

const FLAGS_TABLE_PATTERNS = [
  "FROM FLAGS",
  "FROM`FLAGS`",
  'FROM"FLAGS"',
  "JOIN FLAGS",
  "JOIN`FLAGS`",
  'JOIN"FLAGS"',
  "FLAGS WHERE",
  "FLAGS.",
];

export function isAccessingFlagsTable(input: string): boolean {
  const normalized = input.toUpperCase().replace(/\s+/g, " ");
  return (
    FLAGS_TABLE_PATTERNS.some((pattern) => normalized.includes(pattern)) ||
    /FLAGS\s*[,\s]/.test(normalized)
  );
}

/**
 * Rows come back from a query the player controls: drop flag values before they
 * reach the response. Matching on the `OSS{` prefix rather than on the word
 * "flag" keeps schema enumeration readable — `sqlite_master` names the flags
 * table, and hiding that would only make the challenge opaque.
 */
export function stripFlagValues(
  rows: Record<string, unknown>[]
): Record<string, unknown>[] {
  return rows
    .map((row) => {
      const sanitized: Record<string, unknown> = {};
      for (const key in row) {
        const value = row[key];
        const isFlagValue =
          typeof value === "string" && value.toLowerCase().includes("oss{");
        if (!isFlagValue) sanitized[key] = value;
      }
      return sanitized;
    })
    .filter((row) => Object.keys(row).length > 0);
}
