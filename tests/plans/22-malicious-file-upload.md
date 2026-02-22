# Test Plan: Malicious File Upload (SVG XSS)

**Slug:** `malicious-file-upload`
**Flag:** `OSS{m4l1c10us_f1l3_upl04d_xss}`
**Category:** INJECTION
**Difficulty:** HARD

## Vulnerability Summary

The `POST /api/admin/products/[id]/image` endpoint accepts SVG file uploads. When an SVG file contains malicious content (script tags, event handlers like `onload`, `onerror`, `onclick`, `onmouseover`, or `javascript:` URLs), the endpoint detects it and returns the flag. The file is still saved and served without sanitization.

## Source Files

- `app/api/admin/products/[id]/image/route.ts`

## Test Type

**Jest API test** — `tests/api/malicious-file-upload.test.ts`

## Prerequisites

- Admin authentication required.
- At least one product must exist in the database.

## Test Scenarios

### 1. SVG with script tag returns flag

**Steps:**

1. Login as `admin@oss.com` / `admin`.
2. Get a product ID from `GET /api/products`.
3. Create an SVG file with malicious content:
   ```svg
   <svg xmlns="http://www.w3.org/2000/svg"><script>alert('XSS')</script></svg>
   ```
4. Send `POST /api/admin/products/[productId]/image` as `multipart/form-data` with the SVG file.
5. Assert response status is `200`.
6. Assert response body contains `flag` equal to `OSS{m4l1c10us_f1l3_upl04d_xss}`.

### 2. SVG with onload event handler returns flag

**Steps:**

1. Login as admin.
2. Upload SVG: `<svg xmlns="http://www.w3.org/2000/svg" onload="alert('XSS')"><rect width="100" height="100"/></svg>`
3. Assert response contains `flag`.

### 3. SVG with onerror returns flag

**Steps:**

1. Login as admin.
2. Upload SVG: `<svg xmlns="http://www.w3.org/2000/svg"><image href="x" onerror="alert(1)"/></svg>`
3. Assert response contains `flag`.

### 4. Clean SVG does NOT return flag

**Steps:**

1. Login as admin.
2. Upload clean SVG: `<svg xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="blue"/></svg>`
3. Assert response status is `200`.
4. Assert response body does NOT contain `flag`.
5. Assert response contains `imageUrl`.

### 5. Non-SVG image upload does not check for malicious content

**Steps:**

1. Login as admin.
2. Upload a small valid JPEG file.
3. Assert response status is `200`.
4. Assert response body does NOT contain `flag`.

### 6. Non-admin cannot upload

**Steps:**

1. Login as `alice@example.com`.
2. Attempt to upload an image.
3. Assert response status is `403`.

### 7. File size limit enforced

**Steps:**

1. Login as admin.
2. Attempt to upload a file larger than 5MB.
3. Assert response status is `400`.
4. Assert error mentions "File size exceeds 5MB limit".

## Implementation Notes

- The endpoint uses `multipart/form-data` with field name `image`.
- `containsMaliciousContent()` checks (case-insensitive): `<script`, `onload=`, `onerror=`, `onclick=`, `onmouseover=`, `javascript:`.
- SVG detection: `file.type === "image/svg+xml" || file.name.endsWith(".svg")`.
- Allowed content types: `image/jpeg`, `image/png`, `image/gif`, `image/webp`, `image/svg+xml`.
- Max file size: 5MB.
- The file IS saved even when malicious — the flag is returned alongside the `imageUrl`.
- Use `FormData` API in tests to construct the multipart request.
- Set the file's MIME type to `image/svg+xml` when creating the Blob/File.
