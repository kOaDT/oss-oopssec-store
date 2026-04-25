# Race Condition — Coupon Abuse (TOCTOU)

## Overview

A Time-of-Check Time-of-Use (TOCTOU) bug appears whenever a program reads shared state, decides what to do based on that read, and then acts in a separate operation. If anything else can change the state during the gap, the action can fire on a snapshot that is no longer valid.

In this challenge, the checkout flow reads a coupon's `usedCount`, compares it against `maxUses`, and only afterwards increments the counter in a second database call. Many concurrent orders all read the same `usedCount = 0` before any of them gets to write, so they all believe the coupon is still valid and all consume the same single-use discount.

## Why This Is Dangerous

- **Single-use codes redeemed many times** — promo codes, gift cards, and referral credits exceed their advertised limits.
- **Direct revenue loss** — each successful race grants an unintended discount or credit.
- **Inventory oversell and chargebacks** — the same pattern applies to flash-sale stock and balance withdrawals.
- **Hard to spot in code review** — both Prisma calls look perfectly correct in isolation; the bug is in the lack of atomicity between them.

## Vulnerable Code

```typescript
const coupon = await prisma.coupon.findUnique({
  where: { code: couponCode.toUpperCase() },
});

if (
  coupon &&
  (!coupon.expiresAt || coupon.expiresAt >= new Date()) &&
  coupon.usedCount < coupon.maxUses
) {
  await new Promise((r) => setTimeout(r, 150));

  const updated = await prisma.coupon.update({
    where: { code: coupon.code },
    data: { usedCount: { increment: 1 } },
  });

  expectedTotal = calculatedTotal * (1 - coupon.discount);
}
```

Two distinct database round-trips around shared state, with no transaction and no atomic conditional update. The artificial 150ms delay widens the window the way real validation logic (fraud checks, address lookup, payment authorization) would in production.

## Secure Implementation

Make the check and the increment a single, atomic operation against the database.

**Atomic conditional update (preferred).** A single `UPDATE … WHERE` statement that only succeeds when the predicate holds — no separate "check" round-trip exists:

```typescript
const updated = await prisma.coupon.updateMany({
  where: {
    code: couponCode.toUpperCase(),
    usedCount: { lt: prisma.coupon.fields.maxUses },
    OR: [{ expiresAt: null }, { expiresAt: { gte: new Date() } }],
  },
  data: { usedCount: { increment: 1 } },
});

if (updated.count === 0) {
  // coupon already exhausted or expired — skip the discount
}
```

**Explicit transaction with row locking.** When the database engine supports it, take a row lock inside a transaction so the read and the update see consistent state:

```typescript
await prisma.$transaction(async (tx) => {
  const coupon = await tx.coupon.findUnique({ where: { code } });
  if (!coupon || coupon.usedCount >= coupon.maxUses) {
    throw new Error("Coupon exhausted");
  }
  await tx.coupon.update({
    where: { code },
    data: { usedCount: { increment: 1 } },
  });
});
```

The general principle: any check-then-act on shared state must collapse into a single atomic step at the storage layer. Application-level locks, in-process mutexes, and "validate, then write" sequences all break under concurrent load.

## References

- [CWE-362: Concurrent Execution Using Shared Resource with Improper Synchronization](https://cwe.mitre.org/data/definitions/362.html)
- [CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition](https://cwe.mitre.org/data/definitions/367.html)
- [PortSwigger — Race conditions](https://portswigger.net/web-security/race-conditions)
- [HackerOne #759247 — Race condition on coupon redemption](https://hackerone.com/reports/759247)
