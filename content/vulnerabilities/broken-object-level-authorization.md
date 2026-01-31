# Broken Object Level Authorization (BOLA)

## Overview

This vulnerability demonstrates a Broken Object Level Authorization (BOLA) flaw in the wishlist feature. The API authenticates users but fails to verify that the requested wishlist belongs to the authenticated user. Any logged-in user can access any other user's private wishlists, including internal ones containing sensitive information, by manipulating the wishlist identifier in API requests.

## Why This Is Dangerous

### Authentication Is Not Authorization

BOLA is the #1 risk in the OWASP API Security Top 10. It occurs when an API endpoint accepts an object identifier from the client and does not verify that the authenticated user has permission to access that specific object. The distinction is critical:

1. **Authentication** confirms _who_ the user is (valid credentials, valid session)
2. **Authorization** confirms _what_ the user is allowed to access (ownership, role, permissions)

Many applications correctly implement authentication but neglect object-level authorization checks, assuming that if a user is logged in, they should be able to access any resource they request.

### Impact in E-Commerce

- **Privacy violation** - Access to other users' private wishlists reveals purchasing intent and personal preferences
- **Business intelligence leakage** - Internal procurement or supplier wishlists may expose strategic decisions
- **Data exposure** - Wishlist notes and metadata may contain sensitive internal information
- **Regulatory risk** - Unauthorized access to personal data violates GDPR, CCPA, and similar regulations

## The Vulnerability

The wishlist detail endpoint (`GET /api/wishlists/[id]`) retrieves a wishlist by its identifier without verifying that the authenticated user is the owner. The server:

1. Validates the user's JWT token (authentication)
2. Accepts the wishlist ID from the URL path
3. Queries the database for the wishlist
4. Returns the full wishlist data including items, owner email, and notes
5. **Does not check** that `wishlist.userId` matches the authenticated user's ID

The UI only displays the current user's wishlists, creating a false sense of security. However, the API returns any wishlist regardless of ownership when called directly.

## Exploitation

### How to Retrieve the Flag

To retrieve the flag `OSS{brok3n_0bj3ct_l3v3l_4uth0r1z4t10n}`, you need to exploit the BOLA vulnerability on the wishlists API:

**Exploitation Steps:**

1. Log in as any user (e.g., alice@example.com / iloveduck)
2. Navigate to the Wishlists page and create or view a wishlist
3. Observe the API calls in your browser's developer tools (Network tab)
4. Note the wishlist ID format used in `GET /api/wishlists/[id]` requests
5. Discover other wishlist IDs (e.g., by observing the predictable seeded ID format `wl-*`)
6. Send a request to `GET /api/wishlists/wl-internal-001` using your own authentication token
7. The API returns the admin's internal wishlist containing the flag in the response

### Secure Implementation

```typescript
// VULNERABLE - No ownership check
const wishlist = await prisma.wishlist.findUnique({
  where: { id },
  include: { items: { include: { product: true } } },
});

if (!wishlist) {
  return NextResponse.json({ error: "Wishlist not found" }, { status: 404 });
}

return NextResponse.json(wishlist);

// SECURE - Verifies ownership
const wishlist = await prisma.wishlist.findFirst({
  where: {
    id,
    userId: user.id,
  },
  include: { items: { include: { product: true } } },
});

if (!wishlist) {
  return NextResponse.json({ error: "Wishlist not found" }, { status: 404 });
}

return NextResponse.json(wishlist);
```

The secure version incorporates the user ID directly into the database query, ensuring users can only retrieve their own wishlists. Non-owned wishlists are treated identically to non-existent ones, preventing information leakage about the existence of other users' resources.

## References

- [OWASP API Security Top 10 - API1:2023 Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
- [OWASP Top 10 - A01:2021 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
