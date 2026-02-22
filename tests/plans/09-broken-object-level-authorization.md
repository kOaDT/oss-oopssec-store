# Test Plan: Broken Object Level Authorization (BOLA)

**Slug:** `broken-object-level-authorization`
**Flag:** `OSS{brok3n_0bj3ct_l3v3l_4uth0r1z4t10n}`
**Category:** AUTHORIZATION
**Difficulty:** MEDIUM

## Vulnerability Summary

The `GET /api/wishlists/[id]` endpoint retrieves wishlist details without checking ownership. When a non-admin user accesses another user's wishlist, the flag is returned. The admin's internal wishlist has the known ID `wl-internal-001`.

## Source Files

- `app/api/wishlists/[id]/route.ts`

## Test Type

**Jest API test** — `tests/api/broken-object-level-authorization.test.ts`

## Prerequisites

- A seeded database with wishlists, including the admin's wishlist `wl-internal-001`.
- User accounts: Alice (CUSTOMER) and Admin.

## Test Scenarios

### 1. Non-admin accessing admin's wishlist returns flag

**Steps:**

1. Login as `alice@example.com` / `iloveduck`.
2. Send `GET /api/wishlists/wl-internal-001` with Alice's auth cookie.
3. Assert response status is `200`.
4. Assert response body contains `flag` equal to `OSS{brok3n_0bj3ct_l3v3l_4uth0r1z4t10n}`.
5. Assert response body contains wishlist details (name, items, ownerEmail).

### 2. Admin accessing own wishlist does NOT return flag

**Steps:**

1. Login as `admin@oss.com` / `admin`.
2. Send `GET /api/wishlists/wl-internal-001` with admin's auth cookie.
3. Assert response status is `200`.
4. Assert response body does NOT contain a `flag` property.

### 3. Non-existent wishlist returns 404

**Steps:**

1. Login as `alice@example.com`.
2. Send `GET /api/wishlists/nonexistent-id`.
3. Assert response status is `404`.

### 4. Unauthenticated request is rejected

**Steps:**

1. Send `GET /api/wishlists/wl-internal-001` without auth cookie.
2. Assert response status is `401`.

## Implementation Notes

- The flag condition is: `wishlist.userId !== user.id && user.role !== "ADMIN"`.
- Admin accessing any wishlist does NOT trigger the flag (because of the role check).
- Only non-admin users accessing someone else's wishlist trigger the flag.
- The DELETE endpoint correctly checks ownership — this is NOT vulnerable.
