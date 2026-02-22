# Test Plan: Path Traversal

**Slug:** `path-traversal`
**Flag:** `OSS{p4th_tr4v3rs4l_4tt4ck}`
**Category:** INPUT_VALIDATION
**Difficulty:** MEDIUM

## Vulnerability Summary

The `GET /api/files?file=` endpoint reads files from the `documents/` directory. The `file` parameter is joined directly to the base directory path without proper sanitization. Using `../` sequences, an attacker can escape the `documents/` directory and read arbitrary files, including `flag.txt` at the project root.

## Source Files

- `app/api/files/route.ts`
- `flag.txt` (at project root, contains `OSS{p4th_tr4v3rs4l_4tt4ck}`)

## Test Type

**Jest API test** — `tests/api/path-traversal.test.ts`

## Prerequisites

- The file `flag.txt` must exist at the project root with content including `OSS{p4th_tr4v3rs4l_4tt4ck}`.
- The `documents/` directory must exist.

## Test Scenarios

### 1. Path traversal reads flag.txt

**Steps:**

1. Send `GET /api/files?file=../flag.txt`.
2. Assert response status is `200`.
3. Assert response body `content` contains `OSS{p4th_tr4v3rs4l_4tt4ck}`.

### 2. Normal file access within documents/ works

**Steps:**

1. Send `GET /api/files?file=readme.txt`.
2. Assert response status is `200`.
3. Assert response body contains `filename` and `content`.

### 3. Directory listing works

**Steps:**

1. Send `GET /api/files?list=true`.
2. Assert response status is `200`.
3. Assert response body contains `items` array.

### 4. Missing file parameter returns 400

**Steps:**

1. Send `GET /api/files` (no params).
2. Assert response status is `400`.
3. Assert error mentions "File parameter is required".

### 5. Non-existent file returns 500

**Steps:**

1. Send `GET /api/files?file=nonexistent.txt`.
2. Assert response status is `500`.

### 6. Multiple levels of traversal

**Steps:**

1. Send `GET /api/files?file=../../etc/passwd` (may work depending on path resolution).
2. Assert the server responds (doesn't crash).

## Implementation Notes

- The base directory is `join(process.cwd(), "documents")`.
- The file path is constructed with `join(baseDir, file)` — `path.join` resolves `..` sequences.
- There is NO sanitization check for `..` in the code (the comment in the exploration mentioned a check, but the actual code in `route.ts` has none).
- No authentication required for this endpoint.
- The `flag.txt` file is at the project root (one level above `documents/`).
- For PDF files, the endpoint returns binary content with `Content-Type: application/pdf`.
