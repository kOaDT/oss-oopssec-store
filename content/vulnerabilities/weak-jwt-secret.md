# Weak JWT Secret Vulnerability

## Overview

This vulnerability occurs when a JWT (JSON Web Token) is signed with a weak, easily guessable secret key. While the tokens are properly signed using HS256, the low-entropy secret allows attackers to brute-force or guess the signing key, forge valid tokens, and escalate privileges.

## Root Cause

The vulnerability stems from:

1. **Weak Secret Key**: The JWT signing secret is a common word or short string (e.g., `secret`, `password`, `oopssec`)
2. **No Key Rotation**: The same weak secret is used indefinitely
3. **Trust in Token Claims**: The application trusts the role claim in the JWT without cross-referencing the database

## Impact

This vulnerability allows attackers to:

- Recover the JWT signing secret through brute-force or dictionary attacks
- Forge valid JWT tokens with arbitrary claims
- Escalate privileges by modifying the `role` field
- Gain administrative access without proper authentication
- Access resources restricted to administrators

## Exploitation

### How to Retrieve the Flag

To retrieve the flag `OSS{w34k_jwt_s3cr3t_k3y}`, you need to:

1. **Obtain a valid JWT token**: Log in with a user account to receive a JWT token
2. **Analyze the JWT**: The JWT uses HS256 algorithm:
   - Header: `{"alg":"HS256","typ":"JWT"}`
   - Payload: Contains `id`, `email`, `role`, `hint`, and `exp` fields
   - Signature: HMAC-SHA256 signature
   - Notice the `hint` field: "The secret is not so secret"
3. **Crack the secret**: Use tools like `hashcat` or `john` to brute-force the signing secret
4. **Forge a new token**: Create a new JWT with `role` set to `"ADMIN"` and sign it with the recovered secret
5. **Use the forged token**: Make a request to an admin endpoint with the forged JWT in the Authorization header
6. **Receive the flag**: The system will detect the privilege escalation and return the flag

### Tools for Cracking JWT Secrets

- [**hashcat**](https://github.com/hashcat/hashcat): `hashcat -a 0 -m 16500 jwt.txt wordlist.txt`
- [**john**](https://github.com/openwall/john): `john --wordlist=wordlist.txt --format=HMAC-SHA256 jwt.txt`
- [**jwt_tool**](https://github.com/ticarpi/jwt_tool): `python3 jwt_tool.py <JWT> -C -d wordlist.txt`

## Remediation

### Immediate Actions

1. **Use Strong Secrets**: Generate cryptographically secure random secrets (at least 256 bits)
2. **Use Environment Variables**: Store secrets in environment variables, never hardcode them
3. **Implement Key Rotation**: Regularly rotate signing keys
4. **Validate Against Database**: Cross-reference user roles from the database, not just from JWT claims
5. **Use Asymmetric Algorithms**: Consider using RS256 or ES256 with proper key management

### Code Fixes

**Before (Vulnerable):**

```typescript
const JWT_SECRET = process.env.JWT_SECRET || "secret";

function signHS256(data: string, secret: string): string {
  return crypto.createHmac("sha256", secret).update(data).digest("base64url");
}
```

**After (Secure):**

```typescript
import jwt from "jsonwebtoken";

const createJWT = (payload: object): string => {
  return jwt.sign(payload, process.env.JWT_SECRET, {
    algorithm: "HS256",
    expiresIn: "7d",
  });
};

// Ensure JWT_SECRET is a strong, randomly generated value:
// openssl rand -base64 32
```

## References

- [OWASP JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [CWE-321: Use of Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html)
- [CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)
- [RFC 7519: JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
- [JWT Best Practices](https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/)
