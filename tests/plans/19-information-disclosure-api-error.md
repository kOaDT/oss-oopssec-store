# Test Plan: Information Disclosure via API Error

**Slug:** `information-disclosure-api-error`
**Flag:** `OSS{1nf0_d1scl0sur3_4p1_3rr0r}`
**Category:** INFORMATION_DISCLOSURE
**Difficulty:** EASY

## Vulnerability Summary

The `POST /api/user/export` endpoint exposes system diagnostics when invalid field names are provided. The `getSystemDiagnostics()` function leaks database info, Node version, environment, and the information disclosure flag via `featureFlags`.

## Source Files

- `app/api/user/export/route.ts`

## Test Type

**Jest API test** — `tests/api/information-disclosure-api-error.test.ts`

## Prerequisites

- Authenticated user session.
- The `information-disclosure-api-error` flag in the `flags` table.

## Test Scenarios

### 1. Invalid export field triggers diagnostics leak with flag

**Steps:**

1. Login as `alice@example.com` / `iloveduck`.
2. Send `POST /api/user/export` with body:
   ```json
   { "format": "json", "fields": "invalid_field" }
   ```
3. Assert response status is `400`.
4. Assert response body contains `debug.systemDiagnostics`.
5. Assert `debug.systemDiagnostics.featureFlags` equals `OSS{1nf0_d1scl0sur3_4p1_3rr0r}`.
6. Assert `debug.systemDiagnostics` contains `nodeVersion`, `environment`, `database`.

### 2. Valid export does NOT leak diagnostics

**Steps:**

1. Login as Alice.
2. Send `POST /api/user/export` with body:
   ```json
   { "format": "json", "fields": "email,role" }
   ```
3. Assert response status is `200`.
4. Assert response body contains `data.email` and `data.role`.
5. Assert response body does NOT contain `debug` or `systemDiagnostics`.

### 3. CSV export format works

**Steps:**

1. Login as Alice.
2. Send `POST /api/user/export` with body:
   ```json
   { "format": "csv", "fields": "email,role" }
   ```
3. Assert response status is `200`.
4. Assert response headers contain `Content-Type: text/csv`.

### 4. Missing format/fields returns 400

**Steps:**

1. Login as Alice.
2. Send `POST /api/user/export` with body `{}`.
3. Assert response status is `400`.
4. Assert error mentions "Missing required fields".

### 5. Unauthenticated request is rejected

**Steps:**

1. Send `POST /api/user/export` without auth cookie.
2. Assert response status is `401`.

## Implementation Notes

- Allowed fields: `["id", "email", "role", "addressId", "password"]`.
- When invalid fields are provided, `getSystemDiagnostics()` is called and its output is included in the error response.
- The diagnostics include: `timestamp`, `nodeVersion`, `environment`, `database.connected`, `featureFlags` (which is the flag string from the database).
- The flag is fetched from the database: `prisma.flag.findUnique({ where: { slug: "information-disclosure-api-error" } })`.
