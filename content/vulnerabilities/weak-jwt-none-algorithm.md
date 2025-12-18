# Weak JWT None Algorithm Vulnerability

## Overview

This vulnerability occurs when a JWT (JSON Web Token) is created with the `alg: "none"` algorithm, which means the token has no signature verification. This allows attackers to modify the token payload without detection, potentially escalating privileges or accessing unauthorized resources.

## Vulnerability Summary

The application uses JWTs with `alg: "none"` for authentication. When a JWT uses the "none" algorithm, it means there is no cryptographic signature to verify the token's integrity. This allows anyone who intercepts or receives a JWT to decode it, modify its contents (such as changing the user role to ADMIN), and use the modified token to gain unauthorized access.

## Root Cause

The vulnerability stems from:

1. **No Signature Verification**: The JWT is created with `alg: "none"` in the header
2. **No Server-Side Validation**: The server decodes the JWT but doesn't verify that the user's role in the token matches their actual role in the database
3. **Trust in Client Data**: The application trusts the role claim in the JWT without cross-referencing the database

## Impact

This vulnerability allows attackers to:

- Escalate privileges by modifying the `role` field in the JWT payload
- Gain administrative access without proper authentication
- Access resources restricted to administrators
- Potentially perform unauthorized actions on the system

### Potential Consequences

- Unauthorized privilege escalation
- Access to sensitive administrative functions
- Data manipulation or exfiltration
- System compromise

## Exploitation

### How to Retrieve the Flag

To retrieve the flag `OSS{w34k_jwt_n0n3_4lg0r1thm}`, you need to:

1. **Obtain a valid JWT token**: Log in with user account to receive a JWT token
2. **Decode the JWT**: The JWT uses base64url encoding and can be decoded to see its structure:
   - Header: `{"alg":"none","typ":"JWT"}`
   - Payload: Contains `id`, `email`, `role`, and `exp` fields
3. **Modify the payload**: Change the `role` field from `"CUSTOMER"` to `"ADMIN"`
4. **Re-encode the JWT**: Encode the modified payload back to base64url format
5. **Use the modified token**: Make a request to an admin endpoint with the modified JWT in the Authorization header
6. **Receive the flag**: The system will detect the privilege escalation and return the flag

## Remediation

### Immediate Actions

1. **Use a Secure Algorithm**: Always use a secure signing algorithm like HS256, RS256, or ES256
2. **Verify Signatures**: Always verify JWT signatures on the server side
3. **Validate Against Database**: Cross-reference user roles from the database, not just from JWT claims
4. **Reject None Algorithm**: Explicitly reject JWTs with `alg: "none"` in production
5. **Use Secure Secrets**: Store signing secrets securely and never expose them

### Code Fixes

**Before (Vulnerable):**

```typescript
const createWeakJWT = (payload: object): string => {
  const header = Buffer.from(
    JSON.stringify({ alg: "none", typ: "JWT" })
  ).toString("base64url");
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `${header}.${body}.`;
};
```

**After (Secure):**

```typescript
import jwt from "jsonwebtoken";

const createJWT = (payload: object): string => {
  return jwt.sign(payload, process.env.JWT_SECRET!, {
    algorithm: "HS256",
    expiresIn: "7d",
  });
};
```

## References

- [OWASP JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [CWE-345: Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)
- [RFC 7519: JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
- [JWT Best Practices](https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/)

## Flag

The flag for this vulnerability is: **OSS{w34k_jwt_n0n3_4lg0r1thm}**

The flag can be retrieved by exploiting the JWT "none" algorithm vulnerability to escalate privileges and access the admin endpoint.
