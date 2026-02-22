# Test Plan: Insecure Direct Object Reference (IDOR)

**Slug:** `insecure-direct-object-reference`
**Flag:** `OSS{1ns3cur3_d1r3ct_0bj3ct_r3f3r3nc3}`
**Category:** AUTHORIZATION
**Difficulty:** EASY

## Vulnerability Summary

The `GET /api/orders/[id]` endpoint retrieves order details without verifying that the requesting user owns the order. When a user accesses another user's order, the flag is included in the response.

## Source Files

- `app/api/orders/[id]/route.ts`

## Test Type

**Jest API test** — `tests/api/insecure-direct-object-reference.test.ts`

## Prerequisites

- A seeded database with orders. Bob has orders `ORD-001`, `ORD-002`, `ORD-003`.
- Two user accounts: Alice and Bob.

## Test Scenarios

### 1. Accessing another user's order returns flag

**Steps:**

1. Login as `alice@example.com` / `iloveduck`.
2. Send `GET /api/orders/ORD-001` with Alice's auth cookie.
3. Assert response status is `200`.
4. Assert response body contains `flag` equal to `OSS{1ns3cur3_d1r3ct_0bj3ct_r3f3r3nc3}`.
5. Assert response body contains order details (id, total, status, customerEmail).

### 2. Accessing own order does NOT return flag

**Steps:**

1. Login as `bob@example.com` / `qwerty`.
2. Send `GET /api/orders/ORD-001` with Bob's auth cookie.
3. Assert response status is `200`.
4. Assert response body does NOT contain a `flag` property.

### 3. Non-existent order returns 404

**Steps:**

1. Login as `alice@example.com`.
2. Send `GET /api/orders/ORD-999`.
3. Assert response status is `404`.

### 4. Unauthenticated request is rejected

**Steps:**

1. Send `GET /api/orders/ORD-001` without auth cookie.
2. Assert response status is `401`.

## Implementation Notes

- The flag condition is: `order.userId !== user.id` — the order's owner ID doesn't match the requesting user's ID.
- The order IDs are sequential: `ORD-001`, `ORD-002`, `ORD-003` (all belong to Bob in the seed data).
- Alice accessing Bob's orders triggers the flag. Bob accessing his own orders does not.
