# Test Plan: Weak JWT Secret

**Slug:** `weak-jwt-secret`
**Flag:** `OSS{w34k_jwt_s3cr3t_k3y}`
**Category:** AUTHENTICATION
**Difficulty:** MEDIUM

## Vulnerability Summary

The JWT secret is hardcoded as `"secret"` and is hinted at in the JWT payload itself (`hint: "The secret is not so secret"`). An attacker can decode the JWT, discover the hint, forge a new token with `role: "ADMIN"` for a non-admin user, and access the admin endpoint. When the forged token's user is not an admin in the database but the JWT claims ADMIN role, the weak-jwt-secret flag is returned.

## Source Files

- `lib/server-auth.ts` (JWT creation/verification, secret = `"secret"`)
- `app/api/admin/route.ts` (flag logic)

## Test Type

**Jest unit test** — `tests/unit/weak-jwt-secret.test.ts`
**Jest API test** — `tests/api/weak-jwt-secret.test.ts`

## Prerequisites

- A seeded database with users (Alice is CUSTOMER, Admin is ADMIN).
- The `weak-jwt-secret` flag in the `flags` table.

## Test Scenarios

### Unit Tests (server-auth functions)

#### 1. JWT contains hint in payload

**Steps:**

1. Login as `alice@example.com` / `iloveduck`.
2. Decode the JWT (base64url decode the payload section).
3. Assert the payload contains `hint: "The secret is not so secret"`.

#### 2. JWT can be forged with known secret

**Steps:**

1. Import `createWeakJWT` and `decodeWeakJWT` from `lib/server-auth.ts`.
2. Create a forged token using `createWeakJWT` with Alice's user ID but `role: "ADMIN"`.
3. Verify the token decodes successfully with `decodeWeakJWT`.
4. Assert the decoded payload has `role: "ADMIN"`.

#### 3. hashMD5 produces expected hashes

**Steps:**

1. Import `hashMD5` from `lib/server-auth.ts`.
2. Assert `hashMD5("admin")` equals `21232f297a57a5a743894a0e4a801fc3`.
3. Assert `hashMD5("iloveduck")` produces a valid MD5 hash.

### API Tests

#### 4. Forged admin token for non-admin user returns weak-jwt flag

**Steps:**

1. Import `createWeakJWT` from `lib/server-auth.ts`.
2. Login as `alice@example.com` to get her user ID from the response.
3. Forge a JWT: `createWeakJWT({ id: alice.id, email: "alice@example.com", role: "ADMIN", exp: future_timestamp })`.
4. Send `GET /api/admin` with cookie `authToken=<forged_token>`.
5. Assert response status is `200`.
6. Assert response body contains `flag` equal to `OSS{w34k_jwt_s3cr3t_k3y}`.

#### 5. Legitimate admin access returns MD5 flag (not JWT flag)

**Steps:**

1. Login as `admin@oss.com` / `admin`.
2. Send `GET /api/admin` with admin auth cookie.
3. Assert response status is `200`.
4. Assert response body contains `flag` equal to `OSS{w34k_md5_h4sh1ng}` (NOT the JWT flag).

## Implementation Notes

- The admin endpoint checks: if `dbUser.role !== "ADMIN"` but the JWT says ADMIN → returns `weak-jwt-secret` flag.
- The JWT secret is `process.env.JWT_SECRET || "secret"` — defaults to `"secret"`.
- The `signHS256` function uses `crypto.createHmac("sha256", secret)`.
- Token format: `header.payload.signature` with base64url encoding.
- The hint `"The secret is not so secret"` is added to every JWT payload during login/signup.
