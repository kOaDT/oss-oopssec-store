# Insecure Direct Object Reference (IDOR)

## Overview

IDOR is the close cousin of BOLA: an authenticated endpoint exposes objects keyed by an identifier from the request, and the application does not verify that the caller is allowed to reach that specific object. Predictable identifiers (sequential IDs, dates, slugs derived from public data) make exploitation a matter of incrementing a number.

In this challenge, the order detail endpoint (`GET /api/orders/[id]`) loads an order purely by its public ID, returning customer name, email, delivery address, and order status to whoever asks. Order IDs follow the `ORD-001`, `ORD-002`, ... pattern, so enumeration is trivial.

## Why This Is Dangerous

- **Cross-user data exposure** — any logged-in user reads any order, including PII like names, emails, and shipping addresses.
- **Compliance impact** — GDPR/CCPA-protected data leaves the trust boundary unintended.
- **Predictable IDs amplify reach** — a single attacker can dump every order in seconds.
- **UI-only enforcement is illusory** — hiding orders in the dashboard does not restrict the API behind it.

## Vulnerable Code

```typescript
export const GET = withAuth(async (_request, context, user) => {
  const { id } = await context.params;

  const order = await prisma.order.findUnique({
    where: { id },
    include: {
      user: { include: { address: true } },
      address: true,
    },
  });

  if (!order) {
    return NextResponse.json({ error: "Order not found" }, { status: 404 });
  }

  return NextResponse.json({
    id: order.id,
    total: order.total,
    status: order.status,
    customerName: ...,
    customerEmail: order.user.email,
    deliveryAddress: { ...order.address },
  });
});
```

`withAuth` proves the caller is logged in. The query keys only on `id`, so any valid order ID resolves regardless of `order.userId`.

## Secure Implementation

Filter by ownership at the query layer so non-owners look identical to non-existent records:

```typescript
const order = await prisma.order.findFirst({
  where: { id, userId: user.id },
  include: { address: true },
});

if (!order) {
  return NextResponse.json({ error: "Order not found" }, { status: 404 });
}
```

For admin views or other legitimate cross-user reads, branch the query on `user.role`:

```typescript
const order = await prisma.order.findFirst({
  where: user.role === "ADMIN" ? { id } : { id, userId: user.id },
});
```

Two further hardening steps:

- Use unguessable identifiers (UUIDv4, random nanoid) so even an authorization bug cannot be amplified by trivial enumeration.
- Return 404 instead of 403 for unauthorized access — distinct status codes leak which IDs exist.

## References

- [OWASP API Security Top 10 — API1:2023 Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
- [OWASP Top 10 — A01:2025 Broken Access Control](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
