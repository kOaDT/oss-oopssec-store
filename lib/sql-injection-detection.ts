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

/**
 * Any mention of either table, whatever the quoting or the punctuation that
 * follows: a stored payload reaching `exec()` can drop one outright, and
 * `found_flags` cascades away with it. `hints` holds the level 3 solutions, so
 * one `group_concat` would hand over every walkthrough at once. The underscore
 * in `found_flags` and `revealed_hints` breaks the word boundary, so player
 * progress stays reachable.
 */
export function isAccessingProtectedTable(input: string): boolean {
  return /\b(FLAGS|HINTS)\b/.test(input.toUpperCase());
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
