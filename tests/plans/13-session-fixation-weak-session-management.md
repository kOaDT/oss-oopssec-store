# Test Plan: Session Fixation / Weak Session Management

**Slug:** `session-fixation-weak-session-management`
**Flag:** `OSS{s3ss10n_f1x4t10n_4tt4ck}`
**Category:** AUTHENTICATION
**Difficulty:** MEDIUM

## Vulnerability Summary

The `POST /api/user/support-access` endpoint allows any authenticated user to create a support access token for ANY email, including the admin's. There is no validation that the requesting user owns the target email. The support token can then be used to login as that user via `GET /api/auth/support-login?token=`. When an admin session created via support access hits `GET /api/admin`, the session fixation flag is returned.

## Source Files

- `app/api/user/support-access/route.ts`
- `app/api/auth/support-login/route.ts`
- `app/api/admin/route.ts`

## Test Type

**Jest API test** — `tests/api/session-fixation.test.ts`

## Prerequisites

- Seeded database with admin user (`admin@oss.com`).
- The `session-fixation-weak-session-management` flag in the `flags` table.

## Test Scenarios

### 1. Create support token for admin email as regular user

**Steps:**

1. Login as `alice@example.com` / `iloveduck`.
2. Send `POST /api/user/support-access` with body `{ "email": "admin@oss.com" }` and Alice's auth cookie.
3. Assert response status is `200`.
4. Assert response body contains `supportToken.token`.
5. Assert response body contains `supportLoginUrl` matching `/support-login?token=...`.

### 2. Login via support token grants admin access with flag

**Steps:**

1. Create a support token for `admin@oss.com` (step 1 above).
2. Extract the token value.
3. Send `GET /api/auth/support-login?token=<token>`.
4. Assert response status is `200` (or redirect).
5. Extract the auth cookie from the response.
6. Send `GET /api/admin` with the support-login auth cookie.
7. Assert response contains `flag` equal to `OSS{s3ss10n_f1x4t10n_4tt4ck}`.

### 3. Support token for own email works normally

**Steps:**

1. Login as `alice@example.com`.
2. Send `POST /api/user/support-access` with body `{ "email": "alice@example.com" }` (or empty body, defaults to own email).
3. Assert response status is `200`.
4. Assert a valid token is returned.

### 4. Unauthenticated request is rejected

**Steps:**

1. Send `POST /api/user/support-access` without auth cookie.
2. Assert response status is `401`.

### 5. Non-existent email is rejected

**Steps:**

1. Login as `alice@example.com`.
2. Send `POST /api/user/support-access` with body `{ "email": "nonexistent@example.com" }`.
3. Assert response status is `404`.

## Implementation Notes

- The support access endpoint: `const targetEmail = body.email || user.email;` — defaults to own email if none provided.
- No check that `user.email === targetEmail` — any user can create tokens for any email.
- The support login JWT includes `supportAccess: true` in the payload.
- The admin endpoint checks: `if (user.supportAccess && dbUser.role === "ADMIN")` → returns session fixation flag.
- Tokens expire after 365 days.
