import crypto from "crypto";

/**
 * Each SQL injection challenge hides a canary in the `internal_secrets` table.
 * The flag is only awarded once that canary comes back through the response,
 * which requires a query the vulnerable endpoint can never produce on its own.
 */
export const CANARY_SLUGS = [
  "sql-injection",
  "product-search-sql-injection",
  "second-order-sql-injection",
  "x-forwarded-for-sql-injection",
] as const;

export type CanarySlug = (typeof CANARY_SLUGS)[number];

/** Random suffix: reading the source must not be enough to claim the flag. */
export const generateCanaryToken = (slug: CanarySlug): string =>
  `CANARY-${slug.toUpperCase()}-${crypto.randomBytes(6).toString("hex")}`;

/**
 * `supplied` holds the raw request values that reached the SQL string. A token
 * echoed back verbatim from one of them proves nothing: the player can paste a
 * token it already knows as a SQL literal, or into a field the route stores and
 * reads back. Splitting the token across SQL string concatenation defeats this
 * check, which is accepted: knowing the token at all means the table was read.
 */
export const hasExfiltratedCanary = (
  payload: unknown,
  canary: { token: string } | null,
  supplied: string[]
): boolean => {
  if (!canary) return false;
  if (supplied.some((value) => value.includes(canary.token))) return false;
  return JSON.stringify(payload).includes(canary.token);
};
