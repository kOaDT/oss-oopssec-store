# AES-CBC Padding Oracle Vulnerability

## Overview

This vulnerability demonstrates a padding oracle attack against AES-CBC encrypted share tokens. The application encrypts resource identifiers using AES-256-CBC to generate shareable document links, but fails to authenticate the ciphertext with an HMAC. Combined with distinguishable error responses for padding failures versus resource-not-found conditions, this creates a classic padding oracle that allows attackers to decrypt tokens and forge new ones pointing to arbitrary internal resources.

The padding oracle attack was first described by Serge Vaudenay in 2002 and has since affected many real-world systems including ASP.NET, Ruby on Rails, and various banking applications.

## Vulnerability Summary

The document sharing system encrypts resource paths (e.g., `order:ORD-001`) using AES-256-CBC and serves them via a public share endpoint. When the endpoint receives a token, it attempts to decrypt it and then resolves the referenced resource. The problem is that the server returns different HTTP status codes depending on the failure mode:

1. **400 Bad Request** — When PKCS#7 padding validation fails during AES-CBC decryption
2. **404 Not Found** — When padding is valid but the decrypted resource path doesn't match any known resource
3. **200 OK** — When padding is valid and the resource exists

This three-way distinction leaks a single bit of information per request: whether the padding was valid or not. That single bit is enough to decrypt any ciphertext and forge new ones.

### Vulnerable Code

The encryption utility uses AES-256-CBC without any integrity check:

```typescript
import crypto from "crypto";

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
  // No HMAC verification — ciphertext integrity is not checked
}
```

The share endpoint catches the decryption error separately from the resource lookup:

```typescript
let resourcePath: string;
try {
  resourcePath = decryptShareToken(token);
} catch {
  // Padding error → 400
  return NextResponse.json(
    { error: "Invalid share token format" },
    { status: 400 }
  );
}

// If we get here, padding was valid
// ... lookup resource ...
return NextResponse.json(
  { error: "Shared resource not found" },
  { status: 404 }
);
```

## Impact

An attacker who can observe the server's responses can:

- **Decrypt any share token** to learn the plaintext resource path format
- **Forge tokens for arbitrary resources**, including internal reports not meant to be shared
- **Access confidential data** without authentication, bypassing the intended access control
- **Enumerate internal resource types** by forging tokens for different paths

## Exploitation

### How AES-CBC and PKCS#7 Padding Work

AES-CBC encrypts data in 16-byte blocks. Each plaintext block is XORed with the previous ciphertext block (or the IV for the first block) before encryption. During decryption, the process is reversed: each ciphertext block is decrypted, then XORed with the previous ciphertext block to recover the plaintext.

PKCS#7 padding fills the last block to exactly 16 bytes. If 3 bytes of padding are needed, the padding is `\x03\x03\x03`. If 1 byte is needed, it's `\x01`. A full block of padding (`\x10` repeated 16 times) is added when the plaintext is already a multiple of 16.

The server validates this padding during decryption. If the padding bytes don't follow the PKCS#7 pattern, `decipher.final()` throws an error. The attacker can detect this because the server returns 400 instead of 404.

### The Attack

For a single-block ciphertext (token = IV + 1 cipher block), the attacker:

1. Keeps the cipher block unchanged and modifies the IV
2. For each byte position (from byte 15 down to byte 0), brute-forces all 256 possible values
3. When the server returns non-400 (meaning valid padding), the attacker learns the intermediate decryption value for that byte
4. After recovering all 16 intermediate bytes, computes a new IV that produces any desired plaintext

### How to Retrieve the Flag

To retrieve the flag `OSS{p4dd1ng_0r4cl3_f0rg3d_t0k3n}`:

**Step 1:** Log in and place an order. On the order confirmation page, click "Share Order" to generate a share token.

**Step 2:** Visit the share URL to confirm it works (200 response with order data).

**Step 3:** Modify a byte in the token and observe the response. You should see either 400 (bad padding) or 404 (valid padding, unknown resource).

**Step 4:** Once you can forge arbitrary plaintexts, try an unknown resource type. The server responds with an error message listing the supported types (`order`, `report`), revealing the `report` type.

**Step 5:** Use a padding oracle script to recover the 16 intermediate bytes of the cipher block. This requires up to 4096 requests.

**Step 6:** Compute a new IV so the block decrypts to `report:internal` (with PKCS#7 padding: `report:internal\x01`):

```
new_iv[i] = intermediate[i] XOR target_plaintext_with_padding[i]
```

**Step 7:** Send the forged token (new IV + original cipher block) to the share endpoint. The server decrypts it to `report:internal` and returns the flag.

### Code Fixes

**Before (Vulnerable) — Encrypt-only with distinguishable errors:**

```typescript
try {
  resourcePath = decryptShareToken(token);
} catch {
  return NextResponse.json(
    { error: "Invalid share token format" },
    { status: 400 }
  );
}
// ... resource lookup returns 404 ...
```

**After (Secure) — Use AES-GCM (authenticated encryption):**

```typescript
import crypto from "crypto";

export function encryptShareToken(plaintext: string): string {
  const iv = crypto.randomBytes(12); // GCM uses 12-byte nonces
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

Alternatively, use Encrypt-then-HMAC: compute `HMAC-SHA256(IV + ciphertext)` after encryption and verify it before decryption. If the HMAC doesn't match, reject the token with a generic error before any decryption occurs.

In both cases, return the same error (e.g., 400) regardless of whether the failure was in authentication, padding, or resource lookup.

## References

- [CWE-649: Reliance on Obfuscation or Protection Mechanism that is Not Trusted](https://cwe.mitre.org/data/definitions/649.html)
- [OWASP — Testing for Padding Oracle](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle)
- [OWASP Top 10 — A02:2021 Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [Microsoft — Timing vulnerabilities with CBC-mode symmetric decryption using padding](https://learn.microsoft.com/en-us/dotnet/standard/security/vulnerabilities-cbc-mode)
