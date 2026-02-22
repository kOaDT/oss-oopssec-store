# Test Plan: Client-Side Price Manipulation

**Slug:** `client-side-price-manipulation`
**Flag:** `OSS{cl13nt_s1d3_pr1c3_m4n1pul4t10n}`
**Category:** INPUT_VALIDATION
**Difficulty:** MEDIUM

## Vulnerability Summary

The `POST /api/orders` endpoint accepts a `total` field from the client. While it calculates the actual total from cart items, it uses the client-provided total to create the order. When the client-provided total differs from the calculated total by more than `0.01`, the flag is returned.

## Source Files

- `app/api/orders/route.ts`

## Test Type

**Jest API test** — `tests/api/client-side-price-manipulation.test.ts`
**Cypress E2E test** — `cypress/e2e/client-side-price-manipulation.cy.ts`

## Prerequisites

- Seeded database with products.
- An authenticated user with items in their cart.
- The order creation flow requires: user has an address, items in cart.

## Test Scenarios

### Jest API Tests

#### 1. Order with manipulated price returns flag

**Steps:**

1. Login as `alice@example.com` / `iloveduck`.
2. Add a product to Alice's cart via `POST /api/cart/add` with `{ "productId": "<product_id>", "quantity": 1 }`.
3. Send `POST /api/orders` with body `{ "total": 0.01 }` and Alice's auth cookie.
4. Assert response status is `200`.
5. Assert response body contains `flag` equal to `OSS{cl13nt_s1d3_pr1c3_m4n1pul4t10n}`.
6. Assert response body `total` equals `0.01`.

#### 2. Order with correct price does NOT return flag

**Steps:**

1. Login as a user with items in cart.
2. Get the cart via `GET /api/cart` to calculate the correct total.
3. Send `POST /api/orders` with the correct total.
4. Assert response status is `200`.
5. Assert response body does NOT contain a `flag` property.

#### 3. Order with zero or negative total is rejected

**Steps:**

1. Login.
2. Send `POST /api/orders` with body `{ "total": 0 }`.
3. Assert response status is `400`.

#### 4. Order with empty cart is rejected

**Steps:**

1. Login as a user with an empty cart.
2. Send `POST /api/orders` with body `{ "total": 10 }`.
3. Assert response status is `400`.
4. Assert error mentions "Cart is empty".

### Cypress E2E Test

#### 5. Intercept checkout request and modify price

**Steps:**

1. Login as Alice.
2. Add a product to cart via UI.
3. Go to checkout page.
4. Intercept the `POST /api/orders` request using `cy.intercept()`.
5. Modify the request body to set `total: 0.01`.
6. Complete checkout.
7. Assert the response contains the flag.

## Implementation Notes

- The price validation check: `Math.abs(total - calculatedTotal) > 0.01`.
- The endpoint creates the order with the CLIENT-provided total, not the calculated one.
- Cart items are cleared after order creation.
- Each test that creates an order needs items in the cart first.
- Order IDs are sequential: `ORD-XXX`. Tests may create new orders that increment the counter.
- The endpoint also generates a PDF invoice — this may slow down the response slightly.
