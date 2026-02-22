# Test Plan: React 19 RCE (CVE-2025-55182)

**Slug:** `react2shell`
**Flag:** `OSS{r3act2sh3ll}`
**Category:** REMOTE_CODE_EXECUTION
**Difficulty:** HARD

## Vulnerability Summary

This vulnerability relates to the React 19 Flight protocol and unsafe deserialization leading to prototype pollution and RCE. The flag `OSS{r3act2sh3ll}` is stored in the `.env.local` file as `FLAG_CVE_2025_55182`.

## Source Files

- `.env.local` (contains `FLAG_CVE_2025_55182="OSS{r3act2sh3ll}"`)

## Test Type

**Jest unit test** — `tests/unit/react2shell.test.ts`

## Prerequisites

- `.env.local` must contain `FLAG_CVE_2025_55182="OSS{r3act2sh3ll}"`.
- React version 19.2.0 must be installed (check `package.json`).

## Test Scenarios

### 1. Verify React version is 19.x (vulnerable)

**Steps:**

1. Read `package.json`.
2. Assert `dependencies.react` is `"19.2.0"` or matches `^19`.
3. This confirms the vulnerable React version is in use.

### 2. Verify flag environment variable exists

**Steps:**

1. Read `.env.local` file.
2. Assert it contains `FLAG_CVE_2025_55182="OSS{r3act2sh3ll}"`.

### 3. Verify flag is in the database

**Steps:**

1. Send `POST /api/flags/verify` with body `{ "flag": "OSS{r3act2sh3ll}" }`.
2. Assert response body `valid` is `true`.

## Implementation Notes

- This is a theoretical/documented vulnerability (CVE-2025-55182).
- The actual exploitation involves crafting a malicious payload to the React Flight protocol endpoint.
- Since the exploitation is complex and requires specific conditions, the test focuses on verifying:
  1. The vulnerable React version is installed.
  2. The flag exists and is valid.
  3. The environment variable is properly set.
- The flag is NOT exposed via any API endpoint — it's meant to be discovered by exploiting the React Flight protocol.
- This test is primarily a "canary" to ensure the vulnerability setup hasn't been accidentally patched.
