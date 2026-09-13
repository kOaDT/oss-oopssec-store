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

export const hasExfiltratedCanary = (
  payload: unknown,
  canary: { token: string } | null
): boolean => {
  if (!canary) return false;
  const serialized = JSON.stringify(payload);
  return serialized !== undefined && serialized.includes(canary.token);
};
