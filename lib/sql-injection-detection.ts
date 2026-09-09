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
