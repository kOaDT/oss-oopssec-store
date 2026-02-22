# Test Plan: Product Search SQL Injection

**Slug:** `product-search-sql-injection`
**Flag:** `OSS{pr0duct_s34rch_sql_1nj3ct10n}`
**Category:** INJECTION
**Difficulty:** MEDIUM

## Vulnerability Summary

The `GET /api/products/search?q=` endpoint interpolates the `q` query parameter directly into a raw SQL query. When SQL injection keywords are detected, the flag is returned alongside the search results.

## Source Files

- `app/api/products/search/route.ts`

## Test Type

**Jest API test** — `tests/api/product-search-sql-injection.test.ts`

## Prerequisites

- A seeded database with the `product-search-sql-injection` flag in the `flags` table.
- No authentication required for this endpoint.

## Test Scenarios

### 1. SQL injection attempt returns flag

**Steps:**

1. Send `GET /api/products/search?q=' UNION SELECT 1,2,3,4,5 --`.
2. Assert response status is `200`.
3. Assert response body contains `flag` equal to `OSS{pr0duct_s34rch_sql_1nj3ct10n}`.
4. Assert response body contains `message` equal to `"SQL injection detected"`.

### 2. Flags table access is blocked

**Steps:**

1. Send `GET /api/products/search?q=' UNION SELECT flag FROM flags --`.
2. Assert response status is `403`.
3. Assert response body contains `error` mentioning "Access to flags table is not allowed".

### 3. Normal search works without triggering flag

**Steps:**

1. Send `GET /api/products/search?q=bread`.
2. Assert response status is `200`.
3. Assert response body contains `products` array.
4. Assert response body does NOT contain a `flag` property.

### 4. Empty query returns empty results

**Steps:**

1. Send `GET /api/products/search?q=`.
2. Assert response status is `200`.
3. Assert response body `products` is an empty array.

## Implementation Notes

- This endpoint does NOT require authentication.
- URL-encode the query parameter properly.
- The SQL query uses: `WHERE name LIKE '%${query}%' OR description LIKE '%${query}%'`.
- The flag is returned when `sqlInjectionDetected && flag` — no additional condition on results length unlike order search.
