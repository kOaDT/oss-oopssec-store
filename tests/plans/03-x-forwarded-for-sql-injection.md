# Test Plan: X-Forwarded-For SQL Injection

**Slug:** `x-forwarded-for-sql-injection`
**Flag:** `OSS{x_f0rw4rd3d_f0r_sql1}`
**Category:** INJECTION
**Difficulty:** HARD

## Vulnerability Summary

The `POST /api/tracking` endpoint reads the `X-Forwarded-For` header and inserts its value directly into a raw SQL INSERT query without sanitization. SQL injection keywords in the header trigger detection and flag return.

## Source Files

- `app/api/tracking/route.ts`

## Test Type

**Jest API test** — `tests/api/x-forwarded-for-sql-injection.test.ts`

## Prerequisites

- A seeded database with the `x-forwarded-for-sql-injection` flag in the `flags` table.
- No authentication required.

## Test Scenarios

### 1. SQL injection in X-Forwarded-For returns flag

**Steps:**

1. Send `POST /api/tracking` with:
   - Body: `{ "path": "/", "sessionId": "test" }`
   - Header: `X-Forwarded-For: 127.0.0.1' OR '1'='1`
2. Assert response status is `200`.
3. Assert response body contains `flag` equal to `OSS{x_f0rw4rd3d_f0r_sql1}`.
4. Assert response body contains `message` matching "SQL injection detected".

### 2. Flags table access via header is blocked

**Steps:**

1. Send `POST /api/tracking` with header `X-Forwarded-For: 127.0.0.1' UNION SELECT flag FROM flags --`.
2. Assert response status is `403`.
3. Assert response body contains `error` mentioning "Access to flags table is not allowed".

### 3. Normal tracking request works

**Steps:**

1. Send `POST /api/tracking` with body `{ "path": "/products", "sessionId": "abc" }` without X-Forwarded-For header.
2. Assert response status is `200`.
3. Assert `success` is `true`.
4. Assert response body does NOT contain a `flag` property.

### 4. SQL injection with UNION keyword

**Steps:**

1. Send `POST /api/tracking` with header `X-Forwarded-For: 1' UNION SELECT 1 --`.
2. Assert response status is `200`.
3. Assert response body contains `flag`.

## Implementation Notes

- The detection function also checks for `||` (pipe) as a SQL keyword — unique to this endpoint.
- The INSERT query concatenates the IP directly: `VALUES ('${id}', '${ip}', ...)`.
- The query may fail (error caught silently), but the flag is still returned if injection is detected.
