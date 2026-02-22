# Test Plan: Weak MD5 Hashing

**Slug:** `weak-md5-hashing`
**Flag:** `OSS{w34k_md5_h4sh1ng}`
**Category:** CRYPTOGRAPHIC
**Difficulty:** MEDIUM

## Vulnerability Summary

All passwords are hashed using MD5 (`crypto.createHash("md5")`), which is cryptographically broken and easily reversible via rainbow tables (e.g., crackstation.net). The admin password `admin` produces a well-known MD5 hash. Successfully logging in as admin and accessing `GET /api/admin` returns this flag.

## Source Files

- `lib/server-auth.ts` (`hashMD5` function)
- `app/api/admin/route.ts`
- `app/api/auth/login/route.ts`

## Test Type

**Jest unit test** — `tests/unit/weak-md5-hashing.test.ts`
**Jest API test** — `tests/api/weak-md5-hashing.test.ts`

## Prerequisites

- Seeded database with admin user (`admin@oss.com` / `admin`).
- The `weak-md5-hashing` flag in the `flags` table.

## Test Scenarios

### Unit Tests

#### 1. MD5 hash of "admin" matches known value

**Steps:**

1. Import `hashMD5` from `lib/server-auth.ts`.
2. Assert `hashMD5("admin")` equals `"21232f297a57a5a743894a0e4a801fc3"`.

#### 2. MD5 hash of common passwords produces known hashes

**Steps:**

1. Assert `hashMD5("qwerty")` equals `"d8578edf8458ce06fbc5bb76a58c5ca4"`.
2. Assert `hashMD5("sunshine")` equals `"0571749e2ac330a7455571e220998110"`.
3. Assert `hashMD5("iloveduck")` produces a valid 32-character hex string.

### API Tests

#### 3. Admin login + admin endpoint returns MD5 flag

**Steps:**

1. Login as `admin@oss.com` with password `admin`.
2. Assert login returns status `200` and user role `ADMIN`.
3. Send `GET /api/admin` with the admin auth cookie.
4. Assert response contains `flag` equal to `OSS{w34k_md5_h4sh1ng}`.

#### 4. Admin endpoint accessible after cracking MD5

**Steps:**

1. (This test validates the chain: known MD5 hash → crack → login → admin access)
2. The admin password hash is `21232f297a57a5a743894a0e4a801fc3` which decodes to `admin`.
3. Login with `admin@oss.com` / `admin`.
4. Access `GET /api/admin`.
5. Assert flag is returned.

## Implementation Notes

- The flag is returned in `GET /api/admin` as the last fallback for legitimate admin users (when no other flag condition matches first).
- The admin endpoint checks multiple flag conditions in order: weak-jwt → session-fixation → mass-assignment → md5.
- The MD5 flag is returned when: `dbUser.role === "ADMIN"` AND `dbUser.email` is in the expected emails list AND no other flag conditions triggered first.
- All seeded user passwords use MD5: alice/iloveduck, bob/qwerty, vis.bruta/sunshine, admin/admin.
