# Test Plan: Second-Order SQL Injection

**Slug:** `second-order-sql-injection`
**Flag:** `OSS{s3c0nd_0rd3r_sql_1nj3ct10n}`
**Category:** INJECTION
**Difficulty:** HARD

## Vulnerability Summary

A review's `author` field is stored without sanitization via `POST /api/products/[id]/reviews`. When an admin later filters reviews by author via `GET /api/admin/reviews?author=<payload>`, the stored author value is interpolated into a raw SQL query using better-sqlite3, triggering second-order SQL injection detection.

## Source Files

- `app/api/products/[id]/reviews/route.ts` (storage)
- `app/api/admin/reviews/route.ts` (trigger)

## Test Type

**Jest API test** — `tests/api/second-order-sql-injection.test.ts`

## Prerequisites

- A seeded database with the `second-order-sql-injection` flag.
- A valid user session to create a review.
- An admin session to query reviews by author.
- At least one product must exist (use any seeded product ID).

## Test Scenarios

### 1. Store SQL payload as review author, trigger via admin filter

**Steps:**

1. Get a product ID by calling `GET /api/products` and taking the first product's `id`.
2. Create a review with a SQL injection payload as the author:
   - `POST /api/products/[productId]/reviews` with body:
     ```json
     {
       "content": "Great product!",
       "author": "test' UNION SELECT 1,2,3,4,5,6 --"
     }
     ```
3. Assert review creation returns status `201`.
4. Login as admin (`admin@oss.com` / `admin`).
5. Query admin reviews with the injected author filter:
   - `GET /api/admin/reviews?author=test' UNION SELECT 1,2,3,4,5,6 --`
6. Assert response status is `200`.
7. Assert response body contains `flag` equal to `OSS{s3c0nd_0rd3r_sql_1nj3ct10n}`.
8. Assert response body contains `message` matching "SQL injection detected".

### 2. Flags table access blocked in admin reviews

**Steps:**

1. Login as admin.
2. Send `GET /api/admin/reviews?author=test' UNION SELECT flag FROM flags --`.
3. Assert response status is `403`.

### 3. Normal author filter works without flag

**Steps:**

1. Login as admin.
2. Send `GET /api/admin/reviews?author=alice@example.com`.
3. Assert response status is `200`.
4. Assert response body does NOT contain a `flag` property.

### 4. Non-admin cannot access admin reviews

**Steps:**

1. Login as `alice@example.com`.
2. Send `GET /api/admin/reviews`.
3. Assert response status is `403`.

## Implementation Notes

- The review creation endpoint (`POST /api/products/[id]/reviews`) accepts an `author` field in the body with NO sanitization.
- The admin reviews endpoint uses `better-sqlite3` directly (not Prisma) with string interpolation: `WHERE r.author = '${authorFilter}'`.
- The `isSQLInjectionAttempt` function detects keywords in the author filter param.
- Results are filtered to exclude values containing "flags" or "oss{" (case-insensitive).
- The admin endpoint requires `role === "ADMIN"` from the JWT.
