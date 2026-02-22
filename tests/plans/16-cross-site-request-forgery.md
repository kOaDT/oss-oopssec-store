# Test Plan: Cross-Site Request Forgery (CSRF)

**Slug:** `cross-site-request-forgery`
**Flag:** `OSS{cr0ss_s1t3_r3qu3st_f0rg3ry}`
**Category:** REQUEST_FORGERY
**Difficulty:** MEDIUM

## Vulnerability Summary

The `PATCH /api/orders/[id]` (and `POST`) endpoint updates an order's status. It checks the `Referer` header: if the request does NOT come from `/admin`, it returns the CSRF flag. This simulates a CSRF attack where a malicious page triggers a status update.

## Source Files

- `app/api/orders/[id]/route.ts`
- `public/exploits/csrf-attack.html`

## Test Type

**Jest API test** — `tests/api/cross-site-request-forgery.test.ts`

## Prerequisites

- Seeded database with orders (e.g., `ORD-001`).
- Admin authentication required.
- The `cross-site-request-forgery` flag in the `flags` table.

## Test Scenarios

### 1. Status update without admin referer returns CSRF flag

**Steps:**

1. Login as `admin@oss.com` / `admin`.
2. Send `PATCH /api/orders/ORD-001` with:
   - Body: `{ "status": "SHIPPED" }`
   - Cookie: admin auth token
   - Header: `Referer: https://evil.com/attack`
3. Assert response status is `200`.
4. Assert response body contains `flag` equal to `OSS{cr0ss_s1t3_r3qu3st_f0rg3ry}`.

### 2. Status update from admin dashboard does NOT return flag

**Steps:**

1. Login as admin.
2. Send `PATCH /api/orders/ORD-001` with:
   - Body: `{ "status": "PROCESSING" }`
   - Header: `Referer: http://localhost:3000/admin/orders`
3. Assert response status is `200`.
4. Assert response body does NOT contain a `flag` property.

### 3. Status update with no referer returns flag

**Steps:**

1. Login as admin.
2. Send `PATCH /api/orders/ORD-001` with body `{ "status": "DELIVERED" }` and NO Referer header.
3. Assert response status is `200`.
4. Assert response body contains `flag`.

### 4. Form-encoded POST also works (CSRF simulation)

**Steps:**

1. Login as admin.
2. Send `POST /api/orders/ORD-001` with:
   - Header: `Content-Type: application/x-www-form-urlencoded`
   - Body: `status=CANCELLED`
   - Referer: `https://evil.com`
3. Assert response status is `200`.
4. Assert response body contains `flag`.

### 5. Non-admin cannot update order status

**Steps:**

1. Login as `alice@example.com`.
2. Send `PATCH /api/orders/ORD-001` with body `{ "status": "SHIPPED" }`.
3. Assert response status is `403`.

### 6. Invalid status is rejected

**Steps:**

1. Login as admin.
2. Send `PATCH /api/orders/ORD-001` with body `{ "status": "INVALID" }`.
3. Assert response status is `400`.

## Implementation Notes

- The referer check is: `referer?.includes("/admin")` — any referer containing "/admin" passes.
- Both `PATCH` and `POST` methods trigger the same handler via `updateOrderStatus`.
- The endpoint accepts both JSON and form-encoded data (`application/x-www-form-urlencoded`).
- Valid statuses: `PENDING`, `PROCESSING`, `SHIPPED`, `DELIVERED`, `CANCELLED`.
- The CSRF PoC HTML exists at `public/exploits/csrf-attack.html`.
