# Broken Object Level Authorization (BOLA)

## Overview

BOLA happens when an API authenticates the caller but then trusts the object identifier in the URL or request body without checking that the caller is actually allowed to access that specific object. Authentication ("who are you?") is solved; authorization ("are you allowed to read _this_ record?") is missing.

In this challenge, the wishlist detail endpoint (`GET /api/wishlists/[id]`) loads a wishlist by ID and returns it to any logged-in user. The UI only ever lists the current user's own wishlists, which hides the issue, but the API itself does not scope the lookup to the authenticated user.

## Why This Is Dangerous

- **Cross-tenant data access** — any authenticated user can read any other user's wishlist by guessing or enumerating IDs.
- **Predictable identifiers** — sequential or guessable IDs (`wl-internal-001`, etc.) make enumeration trivial.
- **Privacy and compliance impact** — wishlists carry purchase intent and personal data covered by GDPR/CCPA.
- **Business intelligence leakage** — internal/admin wishlists may expose procurement or strategic data.

## Vulnerable Code

```typescript
export const GET = withAuth(async (_request, context, user) => {
  const { id } = await context.params;

  const wishlist = await prisma.wishlist.findUnique({
    where: { id },
    include: {
      items: { include: { product: true } },
      user: { select: { email: true } },
    },
  });

  if (!wishlist) {
    return NextResponse.json({ error: "Wishlist not found" }, { status: 404 });
  }

  return NextResponse.json(wishlist);
});
```

`withAuth` proves the caller has a valid session, but the query keys only on `id`. Nothing ties the lookup back to `user.id`, so any wishlist ID resolves for any user.

## Secure Implementation

Push the ownership check into the database query so a non-owner gets the same response as a missing record:

```typescript
const wishlist = await prisma.wishlist.findFirst({
  where: {
    id,
    userId: user.id,
  },
  include: {
    items: { include: { product: true } },
  },
});

if (!wishlist) {
  return NextResponse.json({ error: "Wishlist not found" }, { status: 404 });
}

return NextResponse.json(wishlist);
```

For wishlists meant to be shareable (`isPublic`), expand the predicate explicitly: `OR: [{ userId: user.id }, { isPublic: true }]`. The principle is the same — authorization is a property of the query, not a check that lives next to it. Returning 404 instead of 403 also avoids leaking which IDs exist.

## References

- [OWASP API Security Top 10 — API1:2023 Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
- [OWASP Top 10 — A01:2025 Broken Access Control](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
