# Test Plan: Plaintext Password in Logs

**Slug:** `plaintext-password-in-logs`
**Flag:** `OSS{pl41nt3xt_p4ssw0rd_1n_l0gs}`
**Category:** INFORMATION_DISCLOSURE
**Difficulty:** MEDIUM

## Vulnerability Summary

The `POST /api/auth/login` endpoint logs plaintext passwords via `console.log("[auth] login attempt", { email, password, flag: LOGIN_FLAG })`. These logs are written to `logs/app.log` by the instrumentation module and are accessible via `GET /api/monitoring/logs` with hardcoded Basic auth credentials `root:admin`.

## Source Files

- `app/api/auth/login/route.ts` (logging)
- `instrumentation.node.ts` (log capture to file)
- `app/api/monitoring/logs/route.ts` (log access)

## Test Type

**Jest API test** — `tests/api/plaintext-password-in-logs.test.ts`

## Prerequisites

- The application must be running (logs are generated at runtime).
- The `logs/app.log` file must exist (created by instrumentation).
- The monitoring endpoint requires Basic auth: `root:admin`.

## Test Scenarios

### 1. Login triggers log entry with plaintext password

**Steps:**

1. Send `POST /api/auth/login` with `{ "email": "alice@example.com", "password": "iloveduck" }`.
2. Wait briefly for log to be written.
3. Send `GET /api/monitoring/logs` with header `Authorization: Basic cm9vdDphZG1pbg==` (base64 of `root:admin`).
4. Assert response status is `200`.
5. Assert response body `logs` array contains an entry with `password: "iloveduck"`.
6. Assert the log entry also contains `flag: "OSS{pl41nt3xt_p4ssw0rd_1n_l0gs}"`.

### 2. Monitoring endpoint requires authentication

**Steps:**

1. Send `GET /api/monitoring/logs` without auth header.
2. Assert response status is `401`.

### 3. Monitoring endpoint rejects wrong credentials

**Steps:**

1. Send `GET /api/monitoring/logs` with header `Authorization: Basic d3Jvbmc6Y3JlZHM=` (base64 of `wrong:creds`).
2. Assert response status is `401`.

### 4. Monitoring endpoint accepts siem_session cookie

**Steps:**

1. Send `GET /api/monitoring/logs` with cookie `siem_session=authenticated`.
2. Assert response status is `200`.
3. Assert response body contains `logs`.

### 5. Multiple login attempts all logged

**Steps:**

1. Send several login attempts.
2. Access monitoring logs.
3. Assert each attempt appears in the logs with the plaintext password.

## Implementation Notes

- The login route: `console.log("[auth] login attempt", { email, password, flag: LOGIN_FLAG })`.
- The `LOGIN_FLAG` constant is hardcoded in `login/route.ts`: `"OSS{pl41nt3xt_p4ssw0rd_1n_l0gs}"`.
- The instrumentation module captures console.log output and writes to `logs/app.log` as JSON lines.
- The monitoring endpoint auth: Basic auth with `root:admin` OR `siem_session=authenticated` cookie.
- Basic auth header: `Authorization: Basic ` + base64(`root:admin`) = `cm9vdDphZG1pbg==`.
- Log entries may take a moment to be written to disk.
