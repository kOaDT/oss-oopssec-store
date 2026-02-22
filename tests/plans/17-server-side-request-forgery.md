# Test Plan: Server-Side Request Forgery (SSRF)

**Slug:** `server-side-request-forgery`
**Flag:** `OSS{s3rv3r_s1d3_r3qu3st_f0rg3ry}`
**Category:** REQUEST_FORGERY
**Difficulty:** MEDIUM

## Vulnerability Summary

The `POST /api/support` endpoint accepts a `screenshotUrl` parameter and fetches it server-side using `fetch()` without any URL validation. An attacker can supply `http://localhost:3000/internal` to access the internal dashboard page. The support endpoint sends the request with an `X-Internal-Request: true` header, which bypasses the internal page's access check. The internal page (`/internal`) renders the SSRF flag.

## Source Files

- `app/api/support/route.ts` (SSRF trigger)
- `app/internal/page.tsx` (internal page with flag, guarded by `X-Internal-Request` header)

## Test Type

**Jest API test** — `tests/api/server-side-request-forgery.test.ts`

## Prerequisites

- A running application server.
- No authentication required for the support endpoint.
- The `server-side-request-forgery` flag in the `flags` table.

## Test Scenarios

### 1. SSRF to /internal returns page with flag

**Steps:**

1. Send `POST /api/support` with body:
   ```json
   {
     "email": "attacker@evil.com",
     "title": "Test",
     "description": "Test description",
     "screenshotUrl": "http://localhost:3000/internal"
   }
   ```
2. Assert response status is `200`.
3. Assert response body `data.screenshotContent` is NOT null.
4. Assert `screenshotContent` contains the SSRF flag `OSS{s3rv3r_s1d3_r3qu3st_f0rg3ry}`.

### 2. SSRF fetches arbitrary internal API

**Steps:**

1. Send `POST /api/support` with `screenshotUrl: "http://localhost:3000/api/products"`.
2. Assert response status is `200`.
3. Assert `data.screenshotContent` is NOT null.
4. Assert `screenshotContent` contains product data (proving internal fetch works).

### 3. Support request without screenshotUrl works normally

**Steps:**

1. Send `POST /api/support` with body:
   ```json
   { "email": "user@test.com", "title": "Help", "description": "Need help" }
   ```
2. Assert response status is `200`.
3. Assert `data.screenshotContent` is `null`.

### 4. Missing required fields are rejected

**Steps:**

1. Send `POST /api/support` with body `{ "email": "test@test.com" }` (missing title/description).
2. Assert response status is `400`.

### 5. Direct access to /internal without header is redirected

**Steps:**

1. Send `GET /internal` WITHOUT the `X-Internal-Request: true` header.
2. Assert response status is `308` or redirect (Next.js redirect behavior).
3. This confirms the internal page is NOT directly accessible.

## Implementation Notes

- The support endpoint fetches with: `fetch(screenshotUrl, { headers: { "X-Internal-Request": "true" } })`.
- The `/internal` page checks: `headersList.get("x-internal-request") !== "true"` → redirect to `/`.
- Since the support endpoint adds `X-Internal-Request: true`, the internal page renders normally when fetched via SSRF.
- The internal page is a server-rendered React page (not an API route), so the response is HTML.
- The flag is rendered in the HTML body within a `FlagDisplay` component.
- No authentication required for the support endpoint.
- Parse the HTML response to find the flag string in `screenshotContent`.
