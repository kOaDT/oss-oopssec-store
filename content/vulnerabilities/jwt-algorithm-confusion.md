# JWT Algorithm Confusion (RS256 → HS256)

## Overview

A JWT carries the algorithm used to sign it inside its own header. A verifier that reads that `alg` field and dispatches on it lets the token decide how it will be checked — and an attacker controls the token.

Algorithm confusion is the sharpest form of that mistake. An asymmetric algorithm like RS256 splits key material in two: a private key signs, a public key verifies. A symmetric algorithm like HS256 uses one key for both operations. When a verifier accepts both families and feeds them the same key variable, the public key stops being a verification key and starts being a shared secret. The attacker rewrites the header to name HS256, computes an HMAC of the token with the published public key, and the server — which only holds that public key — recomputes the exact same HMAC and accepts the forgery.

The public key is not the flaw. Publishing it is the entire point of asymmetric signing: partners need it to verify webhook callbacks, identity providers publish JWKS documents on purpose. The flaw is a verifier that will treat that public material as a secret if asked politely.

This is a classic migration artefact. The Partner API in this application signed tokens with HS256 and a per-supplier shared secret in v1, moved to RS256 in v2, and kept the HS256 branch alive so v1 integrations would not break during the rollout. The variable that used to hold the shared secret now holds the signing key material, and nobody noticed that the two branches had stopped being independent.

## Why This Is Dangerous

- **Full token forgery** — anyone who can fetch the public key can mint tokens the API treats as genuine, with no access to the private key.
- **Identity spoofing** — every claim becomes attacker-controlled, including the one that names the caller.
- **Horizontal escalation** — in a multi-tenant API, forging the subject claim reads another tenant's data: purchase orders, pricing, contract terms.
- **Vertical escalation** — where a role or scope claim exists, the same forgery grants it.
- **No audit trail** — forged tokens are structurally valid and correctly signed from the server's point of view, so nothing in the logs distinguishes them from real ones.
- **Rotation does not help** — the new public key is published just as deliberately as the old one.

## Vulnerable Code

The Partner API verifier reads `alg` from the token header and branches on it. Both branches read the same `key` variable, which holds the RSA public key PEM:

```typescript
const algorithm = decodeSegment<{ alg?: string }>(header)?.alg;
const key = getPartnerTokenKey();

let signatureIsValid: boolean;
if (algorithm === "RS256") {
  signatureIsValid = crypto.verify(
    "RSA-SHA256",
    Buffer.from(signingInput),
    { key },
    Buffer.from(signature, "base64url")
  );
} else if (algorithm === "HS256") {
  signatureIsValid =
    crypto
      .createHmac("sha256", key)
      .update(signingInput)
      .digest("base64url") === signature;
} else {
  return null;
}
```

`crypto.verify` treats `key` as a public key; `crypto.createHmac` treats the same bytes as a secret. Nothing in the code distinguishes the two roles, because there is only one variable to distinguish.

Hand-rolled verifiers make the flaw easy to see, but this is not where it usually lives. In production it is normally one permissive allow-list left behind by a migration:

```typescript
// Illustrative only — this package is not a dependency of this project.
const claims = jwt.verify(token, key, { algorithms: ["RS256", "HS256"] });
```

That single array is the whole bug. It was added so legacy clients would keep working, and it survived the cleanup that never happened. Modern versions of well-maintained libraries derive the acceptable algorithm family from the key material and refuse the mismatch, which is why the vulnerable pattern here is written by hand — but plenty of deployed code predates those guardrails or reimplements verification for the same "we need to support both" reason.

## Secure Implementation

**Pin exactly one algorithm.** The verifier decides how a token is signed, never the token:

```typescript
const EXPECTED_ALGORITHM = "RS256";

const header = decodeSegment<{ alg?: string }>(encodedHeader);
if (header?.alg !== EXPECTED_ALGORITHM) {
  return null;
}

const signatureIsValid = crypto.verify(
  "RSA-SHA256",
  Buffer.from(signingInput),
  { key: PARTNER_VERIFICATION_PUBLIC_KEY },
  Buffer.from(signature, "base64url")
);
```

**Keep signing and verification key material in separate variables.** A codebase that holds `PARTNER_SIGNING_PRIVATE_KEY` and `PARTNER_VERIFICATION_PUBLIC_KEY`, and never a generic `key` that both code paths reach for, cannot express this bug. Give each key one type, one name and one call site.

If two algorithms genuinely have to coexist during a migration, route them through separate verifier functions with separate key variables, and select between them on something the attacker does not control — the API version in the URL, the credential the client presented, or a `kid` looked up in a key store that also records which algorithm that key is allowed to be used with. Then delete the legacy path on a published date rather than "eventually".

Additional hardening worth applying at the same time:

- Validate `iss`, `aud` and `exp` after the signature check, and reject tokens missing them.
- Compare MACs with a constant-time comparison such as `crypto.timingSafeEqual`.
- Reject `alg: none` explicitly, and never let an empty or missing `alg` fall through to a default.
- Treat the JWKS as a key store, not a key source: pin the keys you expect, and never let a token's `jku` or `jwk` header tell you where to fetch verification material.

## References

- [RFC 8725 — JSON Web Token Best Current Practices, §3.1 "Perform Algorithm Verification"](https://datatracker.ietf.org/doc/html/rfc8725#section-3.1)
- [CWE-347: Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)
- [CVE-2015-9235 — jsonwebtoken: verification bypass through algorithm confusion](https://nvd.nist.gov/vuln/detail/CVE-2015-9235)
- [CVE-2022-23540 — jsonwebtoken: insecure default algorithm handling in verify()](https://nvd.nist.gov/vuln/detail/CVE-2022-23540)
- [OWASP Top 10 — A04:2025 Cryptographic Failures](https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/)
