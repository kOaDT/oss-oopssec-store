# AES-CBC Padding Oracle

## Overview

A padding oracle is created when a server uses AES-CBC without authenticating the ciphertext and exposes a way to distinguish "padding invalid" from "padding valid but content rejected". With that single bit of feedback per request, an attacker can decrypt any ciphertext byte by byte and forge new ciphertexts that decrypt to arbitrary plaintexts of their choice.

In this challenge, the share-link feature encrypts resource identifiers (e.g. `order:ORD-001`) with AES-256-CBC and serves them through a public share endpoint. The endpoint returns different status codes depending on whether PKCS#7 padding validation failed (400) or whether decryption succeeded but the resource was unknown (404), turning the endpoint into a textbook padding oracle.

## Why This Is Dangerous

- **Token decryption** — every share token can be decrypted without knowing the key.
- **Token forgery** — attackers can craft tokens that decrypt to arbitrary internal resource paths.
- **Access-control bypass** — internal resources never intended for external sharing become reachable.
- **Resource enumeration** — error messages on forged tokens leak the set of supported resource types.

## Vulnerable Code

The crypto helper uses unauthenticated AES-CBC:

```typescript
const ALGORITHM = "aes-256-cbc";

export function encryptShareToken(plaintext: string): string {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ALGORITHM, SHARE_KEY, iv);
  const encrypted = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  return Buffer.concat([iv, encrypted]).toString("hex");
}

export function decryptShareToken(tokenHex: string): string {
  const data = Buffer.from(tokenHex, "hex");
  const iv = data.subarray(0, 16);
  const ciphertext = data.subarray(16);
  const decipher = crypto.createDecipheriv(ALGORITHM, SHARE_KEY, iv);
  return Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]).toString("utf8");
}
```

There is no MAC over the ciphertext, so any modification to the IV or cipher block goes undetected until PKCS#7 padding is checked at the end of `decipher.final()`. The share endpoint then handles the two failure modes with distinct status codes:

```typescript
let resourcePath: string;
try {
  resourcePath = decryptShareToken(token);
} catch {
  return NextResponse.json(
    { error: "Invalid share token format" },
    { status: 400 }
  );
}
// padding was valid — resource lookup happens here, returns 404 on miss
```

The 400-vs-404 split is the oracle: it tells the attacker, on every request, whether their tampered ciphertext produced valid PKCS#7 padding.

## Secure Implementation

Use authenticated encryption so that any tampering is rejected before padding is even consulted. AES-GCM is the standard choice in Node:

```typescript
export function encryptShareToken(plaintext: string): string {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", KEY, iv);
  const encrypted = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([iv, authTag, encrypted]).toString("hex");
}

export function decryptShareToken(tokenHex: string): string {
  const data = Buffer.from(tokenHex, "hex");
  const iv = data.subarray(0, 12);
  const authTag = data.subarray(12, 28);
  const ciphertext = data.subarray(28);
  const decipher = crypto.createDecipheriv("aes-256-gcm", KEY, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]).toString("utf8");
}
```

If AES-CBC must be kept, use Encrypt-then-MAC: compute `HMAC-SHA256(IV ‖ ciphertext)` with a separate key, prepend it to the token, and verify it in constant time before any decryption attempt.

In both designs, the endpoint must return the same generic error for every failure (bad MAC, bad padding, unknown resource). Distinguishable error codes are what made this trivially exploitable.

## References

- [CWE-649: Reliance on Obfuscation or Protection Mechanism that is Not Trusted](https://cwe.mitre.org/data/definitions/649.html)
- [OWASP — Testing for Padding Oracle](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle)
- [OWASP Top 10 — A02:2021 Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [Microsoft — Timing vulnerabilities with CBC-mode symmetric decryption using padding](https://learn.microsoft.com/en-us/dotnet/standard/security/vulnerabilities-cbc-mode)
