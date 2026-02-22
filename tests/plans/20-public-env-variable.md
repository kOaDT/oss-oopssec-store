# Test Plan: Public Environment Variable

**Slug:** `public-env-variable`
**Flag:** `OSS{public_3nvir0nment_v4ri4bl3}`
**Category:** INFORMATION_DISCLOSURE
**Difficulty:** EASY

## Vulnerability Summary

The environment variable `NEXT_PUBLIC_PAYMENT_SECRET` is set to a base64-encoded flag value `T1NTe3B1YmxpY18zbnZpcjBubWVudF92NHJpNGJsM30=` in `.env.local`. Since Next.js bundles all `NEXT_PUBLIC_*` variables into client-side JavaScript, this secret is exposed in the browser bundles. Decoding the base64 string reveals the flag.

## Source Files

- `.env.local` (contains `NEXT_PUBLIC_PAYMENT_SECRET`)
- `app/checkout/CheckoutClient.tsx` (references the variable)

## Test Type

**Jest unit test** — `tests/unit/public-env-variable.test.ts`
**Cypress E2E test** — `cypress/e2e/public-env-variable.cy.ts`

## Prerequisites

- `.env.local` must contain `NEXT_PUBLIC_PAYMENT_SECRET="T1NTe3B1YmxpY18zbnZpcjBubWVudF92NHJpNGJsM30="`.

## Test Scenarios

### Unit Tests

#### 1. Base64 value decodes to flag

**Steps:**

1. Decode `T1NTe3B1YmxpY18zbnZpcjBubWVudF92NHJpNGJsM30=` from base64.
2. Assert the decoded value equals `OSS{public_3nvir0nment_v4ri4bl3}`.

#### 2. NEXT_PUBLIC_PAYMENT_SECRET env var exists

**Steps:**

1. Read `.env.local` file content.
2. Assert it contains `NEXT_PUBLIC_PAYMENT_SECRET`.
3. Assert the value is a base64-encoded string.

### Cypress E2E Tests

#### 3. Client-side JS bundles contain the base64 secret

**Steps:**

1. Visit the checkout page or any page that loads the checkout component.
2. Fetch the page source or JS bundles.
3. Assert the bundle contains `T1NTe3B1YmxpY18zbnZpcjBubWVudF92NHJpNGJsM30=`.

#### 4. Verify the flag via the flags API

**Steps:**

1. Decode the base64 string.
2. Submit the decoded value via `POST /api/flags/verify`.
3. Assert the flag is valid.

## Implementation Notes

- The base64 encoding: `T1NTe3B1YmxpY18zbnZpcjBubWVudF92NHJpNGJsM30=` → `OSS{public_3nvir0nment_v4ri4bl3}`.
- Next.js automatically inlines `NEXT_PUBLIC_*` variables into the client-side bundle at build time.
- The variable is used in `app/checkout/CheckoutClient.tsx`: `process.env.NEXT_PUBLIC_PAYMENT_SECRET`.
- The Cypress test should look for the base64 string in the page source or JS assets.
- The unit test can simply verify the base64 decoding logic.
