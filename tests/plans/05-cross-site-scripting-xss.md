# Test Plan: Cross-Site Scripting (XSS)

**Slug:** `cross-site-scripting-xss`
**Flag:** `OSS{cr0ss_s1t3_scr1pt1ng_xss}`
**Category:** INJECTION
**Difficulty:** EASY

## Vulnerability Summary

Product reviews accept arbitrary HTML/script content without sanitization. A stored XSS payload injected via review content is rendered unsanitized in the product page. The flag is stored in `/public/xss-flag.txt` and is meant to be fetched via an XSS payload.

## Source Files

- `app/api/products/[id]/reviews/route.ts`
- `public/xss-flag.txt` (contains `OSS{cr0ss_s1t3_scr1pt1ng_xss}`)

## Test Type

**Jest API test** — `tests/api/cross-site-scripting-xss.test.ts`
**Cypress E2E test** — `cypress/e2e/cross-site-scripting-xss.cy.ts`

## Prerequisites

- A seeded database with products.
- The file `public/xss-flag.txt` must exist with content `OSS{cr0ss_s1t3_scr1pt1ng_xss}`.

## Test Scenarios

### Jest API Tests

#### 1. XSS payload is stored in review without sanitization

**Steps:**

1. Get a product ID from `GET /api/products`.
2. Submit a review with XSS payload:
   - `POST /api/products/[productId]/reviews` with body:
     ```json
     {
       "content": "<script>fetch('/xss-flag.txt').then(r=>r.text()).then(d=>console.log(d))</script>",
       "author": "attacker"
     }
     ```
3. Assert response status is `201`.
4. Assert the review content in the response contains the `<script>` tag verbatim (no sanitization).

#### 2. XSS flag file is accessible

**Steps:**

1. Send `GET /xss-flag.txt` (served from `public/`).
2. Assert response status is `200`.
3. Assert response body contains `OSS{cr0ss_s1t3_scr1pt1ng_xss}`.

#### 3. Review with script tag is returned unsanitized in GET

**Steps:**

1. After storing the XSS review, send `GET /api/products/[productId]/reviews`.
2. Assert at least one review has `content` containing `<script>`.

### Cypress E2E Tests

#### 4. XSS payload renders in product page

**Steps:**

1. Visit a product page.
2. Submit a review with content: `<img src=x onerror="document.title='XSS'">`.
3. Assert the review is displayed on the page with the unsanitized HTML.

## Implementation Notes

- The review `POST` endpoint accepts `content` and `author` directly from the request body.
- No HTML sanitization is applied at any point (storage or rendering).
- The `xss-flag.txt` file is in the `public/` directory and served by Next.js static file serving.
- For Cypress tests, use `dangerouslySetInnerHTML` detection or check that raw HTML is present in the DOM.
