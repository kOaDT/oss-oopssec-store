# Weak JWT Secret

## Overview

A JWT signed with a low-entropy HMAC secret is a public token in disguise. The signing process itself is fine — HS256 is a sound algorithm — but the security of an HMAC token depends entirely on the attacker's inability to recover the key. Once the secret is guessable, anyone can mint tokens with arbitrary claims and pass server-side verification.

In this challenge, the JWT secret defaults to `"secret"` and the issued tokens carry a `hint` claim ("The secret is not so secret") that all but advertises the weakness. The rest of the application trusts the `role` claim verbatim, so a forged token with `role: "ADMIN"` is enough for full administrative access.

## Why This Is Dangerous

- **Offline attack** — once the attacker has any signed token, they can crack the secret offline at full CPU/GPU speed.
- **Free token forging** — with the secret recovered, attackers mint tokens with any `id`, `email`, or `role` they want.
- **Privilege escalation** — the application trusts JWT claims as the source of truth for identity and authorization.
- **No detection signal** — forged tokens look identical to legitimate ones; nothing in normal logs flags them.

## Vulnerable Code

```typescript
const JWT_SECRET = process.env.JWT_SECRET || "secret";

function signHS256(data: string, secret: string): string {
  return crypto.createHmac("sha256", secret).update(data).digest("base64url");
}

export function createWeakJWT(payload: object): string {
  const header = Buffer.from(
    JSON.stringify({ alg: "HS256", typ: "JWT" })
  ).toString("base64url");
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = signHS256(`${header}.${body}`, JWT_SECRET);
  return `${header}.${body}.${signature}`;
}
```

The fallback secret `"secret"` is in every wordlist; even without the `hint` field, hashcat (`-m 16500`) recovers it in milliseconds. Once the secret is known, generating a new token with `role: "ADMIN"` is one line of code.

## Secure Implementation

Use a high-entropy secret, and stop trusting JWT claims as the only source of authorization data.

**Generate the secret with a CSPRNG** and load it from a secret manager — no fallback:

```typescript
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  throw new Error("JWT_SECRET must be set to a 32+ byte random value");
}
// $ openssl rand -base64 48
```

**Prefer a vetted JWT library.** Hand-rolling HS256 is fine pedagogically, but production code benefits from libraries that enforce algorithm pinning and reject tokens with `alg: "none"` or with a different algorithm than the one configured:

```typescript
import jwt from "jsonwebtoken";

const token = jwt.sign(payload, JWT_SECRET, {
  algorithm: "HS256",
  expiresIn: "7d",
});

const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ["HS256"] });
```

**Re-fetch authorization from the database.** A token tells the server _who_ the user claims to be; the database tells it _what_ that user is allowed to do. Never grant admin access based purely on a `role` field in a JWT — verify it server-side on every privileged action.

**Consider asymmetric signatures.** RS256/ES256 means the signing key (private) lives only on the issuer; verifiers only need the public key. Even if a verifier is compromised, the attacker cannot mint tokens.

## References

- [OWASP — JWT for Java Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [CWE-321: Use of Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html)
- [CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)
- [RFC 7519: JSON Web Token (JWT)](https://www.rfc-editor.org/rfc/rfc7519)
- [RFC 8725: JWT Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725)
