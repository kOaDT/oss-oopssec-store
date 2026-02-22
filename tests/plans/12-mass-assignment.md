# Test Plan: Mass Assignment

**Slug:** `mass-assignment`
**Flag:** `OSS{m4ss_4ss1gnm3nt_vuln3r4b1l1ty}`
**Category:** INPUT_VALIDATION
**Difficulty:** MEDIUM

## Vulnerability Summary

The `POST /api/auth/signup` endpoint accepts a `role` field in the request body. When provided, it sets the user's role directly without validation. An attacker can sign up with `role: "ADMIN"` to create an admin account. Accessing `GET /api/admin` with this new admin account (whose email is NOT in the expected list) returns the mass assignment flag.

## Source Files

- `app/api/auth/signup/route.ts`
- `app/api/admin/route.ts`

## Test Type

**Jest API test** — `tests/api/mass-assignment.test.ts`

## Prerequisites

- A seeded database.
- The `mass-assignment` flag in the `flags` table.

## Test Scenarios

### 1. Signup with role ADMIN creates admin account

**Steps:**

1. Send `POST /api/auth/signup` with body:
   ```json
   {
     "email": "attacker-mass@evil.com",
     "password": "password123",
     "role": "ADMIN"
   }
   ```
2. Assert response status is `200`.
3. Assert response body `user.role` equals `"ADMIN"`.
4. Extract the auth cookie from the response.

### 2. New admin account triggers mass assignment flag

**Steps:**

1. Create an admin account via signup (step 1 above).
2. Send `GET /api/admin` with the auth cookie.
3. Assert response status is `200`.
4. Assert response body contains `flag` equal to `OSS{m4ss_4ss1gnm3nt_vuln3r4b1l1ty}`.

### 3. Normal signup without role creates CUSTOMER

**Steps:**

1. Send `POST /api/auth/signup` with body:
   ```json
   { "email": "normal-user-test@example.com", "password": "password123" }
   ```
2. Assert response status is `200`.
3. Assert response body `user.role` equals `"CUSTOMER"`.

### 4. Duplicate email is rejected

**Steps:**

1. Send `POST /api/auth/signup` with body:
   ```json
   { "email": "alice@example.com", "password": "test" }
   ```
2. Assert response status is `409`.

## Implementation Notes

- The signup route checks `if (body.role) { userData.role = body.role as UserRole; }`.
- The admin endpoint returns the mass assignment flag when: `dbUser.role === "ADMIN"` AND `!expectedEmails.includes(dbUser.email)`.
- Expected emails: `["alice@example.com", "bob@example.com", "admin@oss.com", "vis.bruta@example.com"]`.
- Use a unique email for each test run to avoid conflicts (consider using timestamps or UUID in the email).
- **Cleanup consideration:** Tests create users in the database. Consider using unique emails per test run.
