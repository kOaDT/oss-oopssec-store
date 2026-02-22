# Test Plan: SQL Injection (Order Search)

**Slug:** `sql-injection`
**Flag:** `OSS{sql_1nj3ct10n_vuln3r4b1l1ty}`
**Category:** INJECTION
**Difficulty:** MEDIUM

## Vulnerability Summary

The `POST /api/orders/search` endpoint accepts a `status` field in the request body and interpolates it directly into a raw SQL query without parameterization. When a SQL injection attempt is detected (via keyword matching), the endpoint returns the flag.

## Source Files

- `app/api/orders/search/route.ts`

## Test Type

**Jest API test** — `tests/api/sql-injection.test.ts`

## Prerequisites

- A seeded database with the `sql-injection` flag in the `flags` table.
- A valid user session (authenticated as any user, e.g., `alice@example.com` / `iloveduck`).

## Test Scenarios

### 1. SQL injection attempt returns flag

**Steps:**

1. Login as `alice@example.com` with password `iloveduck` via `POST /api/auth/login`.
2. Extract the `authToken` cookie from the login response.
3. Send `POST /api/orders/search` with body `{ "status": "PENDING' UNION SELECT 1,2,3,4,5,6,7,8,9 --" }` and the auth cookie.
4. Assert response status is `200`.
5. Assert response body contains `flag` equal to `OSS{sql_1nj3ct10n_vuln3r4b1l1ty}`.
6. Assert response body contains `message` equal to `"SQL injection detected"`.

### 2. Flags table access is blocked

**Steps:**

1. Login as `alice@example.com`.
2. Send `POST /api/orders/search` with body `{ "status": "PENDING' UNION SELECT flag FROM flags --" }`.
3. Assert response status is `403`.
4. Assert response body contains `error` mentioning "Access to flags table is not allowed".

### 3. Normal status filter works without triggering flag

**Steps:**

1. Login as `alice@example.com`.
2. Send `POST /api/orders/search` with body `{ "status": "PENDING" }`.
3. Assert response status is `200`.
4. Assert response body does NOT contain a `flag` property.

### 4. Unauthenticated request is rejected

**Steps:**

1. Send `POST /api/orders/search` without auth cookie, body `{ "status": "PENDING" }`.
2. Assert response status is `401`.

## Implementation Notes

- Use the `login()` and `authHeaders()` helpers from `tests/helpers/api.ts`.
- The `isSQLInjectionAttempt` function checks for keywords: UNION, SELECT, INSERT, UPDATE, DELETE, DROP, etc.
- The flag is only returned when `sqlInjectionDetected && flag && results.length > 0`, but the UNION query may not return results — verify behavior. If needed, use a simpler injection like `PENDING' OR '1'='1` which contains `OR '1'='1`.
- The flags table access check normalizes whitespace and checks multiple patterns.
