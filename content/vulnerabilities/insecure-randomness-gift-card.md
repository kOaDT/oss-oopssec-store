# Insecure Randomness — Gift Card Code Generation

## Overview

The store sells digital gift cards in fixed denominations and emails the recipient a redemption code in the form `XXXX-XXXX-XXXX`. The code is the only thing protecting the value stored on the card; whoever knows it can redeem it.

The vulnerability is that the code is not random. It is derived from the card's creation timestamp using a classic Numerical-Recipes-style linear congruential generator (LCG). Anyone who can read the card's `createdAt` value — and the buyer-facing `GET /api/gift-cards` endpoint serves it back to the buyer with millisecond precision — can reproduce the code without ever seeing the email.

## Why This Is Dangerous

- **Stealable value without account access** — codes can be regenerated from public metadata, no inbox required.
- **Trivial brute force when the timestamp is fuzzy** — even an unknown second leaves only ~1000 candidates per card.
- **Bulk harvesting** — any leak of timestamps (analytics logs, email `Date` headers) multiplies into recoverable codes.
- **Wider PRNG misuse pattern** — the same anti-pattern shows up in password-reset tokens, invite tokens, OTPs, and signed download links.

This class of flaw is covered by [CWE-330](https://cwe.mitre.org/data/definitions/330.html) and [CWE-338](https://cwe.mitre.org/data/definitions/338.html).

## Vulnerable Code

`lib/gift-card.ts` derives the code deterministically from a 32-bit seed:

```typescript
function nextState(state: number): number {
  return (Math.imul(state, 1103515245) + 12345) & 0x7fffffff;
}

export function generateGiftCardCode(seed: number): string {
  let state = seed & 0x7fffffff;
  const chars: string[] = [];
  for (let i = 0; i < 12; i++) {
    state = nextState(state);
    const index = (state >>> 16) % ALPHABET.length;
    chars.push(ALPHABET[index]);
  }
  // formatted as XXXX-XXXX-XXXX
}
```

Two compounding issues:

1. The LCG constants `(1103515245, 12345, 2^31)` are public, so the sequence is fully recoverable from the seed.
2. The seed is `createdAt.getTime()`, and `GET /api/gift-cards` returns `createdAt` to whoever is authenticated as the buyer of the card — so any compromise of (or known credentials for) the buyer account hands the seed to the attacker.

## Secure Implementation

Generate codes from a cryptographically secure RNG and store only their hash:

```typescript
import { randomBytes, createHash } from "node:crypto";

const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

export function generateGiftCardCode(): string {
  const bytes = randomBytes(12);
  const chars: string[] = [];
  for (let i = 0; i < 12; i++) {
    chars.push(ALPHABET[bytes[i] % ALPHABET.length]);
  }
  return `${chars.slice(0, 4).join("")}-${chars.slice(4, 8).join("")}-${chars.slice(8, 12).join("")}`;
}

const code = generateGiftCardCode();
const codeHash = createHash("sha256").update(code).digest("hex");
// store `codeHash`; show `code` once, in the recipient's email
```

A 12-character draw from a 32-character alphabet carries ~60 bits of entropy — large enough that enumeration is infeasible. Hashing the stored value means a database leak does not reveal redeemable codes.

Two more controls worth applying together:

- **Trim the metadata you expose.** Do not return `createdAt` at millisecond precision (or at all) to any client that could correlate it with redeemable codes. Internal state should not leak through "harmless" timestamps, even on authenticated endpoints.
- **Compare in constant time, redeem atomically.** Use `crypto.timingSafeEqual` for the hash comparison and `UPDATE ... WHERE status = 'PENDING'` for redemption to defeat timing side channels and double-spend races.

## References

- [CWE-330: Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)
- [CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/338.html)
- [OWASP — Insecure Randomness](https://owasp.org/www-community/vulnerabilities/Insecure_Randomness)
- [Node.js `crypto.randomBytes`](https://nodejs.org/api/crypto.html#cryptorandombytessize-callback)
- [Wikipedia — Linear congruential generator](https://en.wikipedia.org/wiki/Linear_congruential_generator)
