# Test Plan: Brute Force / No Rate Limiting

**Slug:** `brute-force-no-rate-limiting`
**Flag:** `OSS{brut3_f0rc3_n0_r4t3_l1m1t}`
**Category:** AUTHENTICATION
**Difficulty:** MEDIUM

## Vulnerability Summary

The `POST /api/auth/login` endpoint has no rate limiting on failed login attempts. The user `vis.bruta@example.com` has the common password `sunshine`. Successfully logging in as this user returns the brute force flag in the login response.

## Source Files

- `app/api/auth/login/route.ts`

## Test Type

**Jest API test** — `tests/api/brute-force-no-rate-limiting.test.ts`

## Prerequisites

- Seeded database with `vis.bruta@example.com` / `sunshine`.
- The `brute-force-no-rate-limiting` flag in the `flags` table.

## Test Scenarios

### 1. Multiple failed login attempts are not rate-limited

**Steps:**

1. Send 10 rapid `POST /api/auth/login` requests with `{ "email": "vis.bruta@example.com", "password": "wrong" }`.
2. Assert ALL responses return status `401` (no rate limiting kicks in, no 429 response).
3. Assert no delay or blocking occurs.

### 2. Successful login after brute force returns flag

**Steps:**

1. Send several failed attempts with wrong passwords.
2. Send `POST /api/auth/login` with `{ "email": "vis.bruta@example.com", "password": "sunshine" }`.
3. Assert response status is `200`.
4. Assert response body contains `flag` equal to `OSS{brut3_f0rc3_n0_r4t3_l1m1t}`.

### 3. Brute force simulation with common passwords

**Steps:**

1. Define a list of common passwords: `["123456", "password", "qwerty", "abc123", "sunshine"]`.
2. Iterate through the list, sending login attempts for `vis.bruta@example.com`.
3. Assert the last attempt (`sunshine`) succeeds with status `200`.
4. Assert the successful response contains the `flag`.

### 4. Other users login does NOT return brute force flag

**Steps:**

1. Login as `alice@example.com` / `iloveduck`.
2. Assert response status is `200`.
3. Assert response body `flag` is `null` (not the brute force flag).

## Implementation Notes

- The flag is returned only for `vis.bruta@example.com`: `const isVisBruta = user.email === "vis.bruta@example.com"`.
- The flag is included directly in the login response body as `flag`.
- There is genuinely no rate limiting middleware on any endpoint.
- The login endpoint also logs plaintext passwords: `console.log("[auth] login attempt", { email, password, flag: LOGIN_FLAG })`.
- The brute force test should send requests sequentially (not in parallel) to simulate realistic attack behavior and avoid overwhelming the test server.
