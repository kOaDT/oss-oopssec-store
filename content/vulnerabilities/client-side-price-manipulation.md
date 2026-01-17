# Client-Side Price Manipulation

## Overview

This vulnerability demonstrates a critical security flaw in e-commerce applications where the total order price is calculated and validated on the client side rather than being recalculated and verified on the server. This allows attackers to manipulate the price they pay by modifying the request payload before it reaches the server.

## Why This Is Dangerous

### Trusting Client-Side Data

When an application accepts price calculations from the client without server-side verification, it creates a fundamental security vulnerability:

1. **Client-side code is under user control** - Users can modify JavaScript, intercept network requests, or use browser developer tools
2. **No server-side validation** - The server blindly trusts the total sent by the client
3. **Direct financial impact** - Attackers can pay less than the actual price of their order
4. **Business logic bypass** - Price calculations, discounts, and taxes can be circumvented

### What This Means

**Never trust client-side calculations for critical business logic.** The server must always:

- Recalculate prices from authoritative sources (database)
- Verify all financial transactions server-side
- Validate that the client's data matches server calculations
- Reject any discrepancies

## The Vulnerability

In this application, the order creation endpoint (`/api/orders`) accepts a `total` value directly from the client without recalculating it from the actual cart contents. The server:

1. Receives the `total` from the client request body
2. Validates only that it's a positive number
3. Creates the order with the client-provided total
4. Does not verify the total against actual product prices

## Root Cause

The vulnerability occurs in `app/api/orders/route.ts`:

- The total is extracted directly from the request body
- The total is used to create the order without server-side recalculation

## Exploitation

### How to Retrieve the Flag

To retrieve the flag `OSS{cl13nt_s1d3_pr1c3_m4n1pul4t10n}`, you need to exploit the price manipulation vulnerability:

**Exploitation Steps:**

1. Add items to cart and go to checkout
2. Open DevTools → Network tab
3. Click "Complete Payment"
4. Find the POST request to `/api/orders`
5. Right-click → Edit and Resend (or use a proxy like Burp Suite)
6. Modify the `total` value in the request body
7. Send the request
8. Check the response - it will contain the flag if the manipulation is detected

**Note:** The server detects the manipulation by comparing the client-provided total with the server-calculated total. If they differ, the flag is returned in the response.

### Secure Implementation

```typescript
// ❌ VULNERABLE - Trusts client total
const { total } = await request.json();
const order = await prisma.order.create({
  data: { userId: user.id, total: total },
});

// ✅ SECURE - Recalculates server-side
const cart = await prisma.cart.findFirst({
  where: { userId: user.id },
  include: { cartItems: { include: { product: true } } },
});

const calculatedTotal = cart.cartItems.reduce(
  (sum, item) => sum + item.product.price * item.quantity,
  0
);

const order = await prisma.order.create({
  data: { userId: user.id, total: calculatedTotal },
});
```

## References

- [OWASP API Security Top 10 - Broken Object Level Authorization](https://owasp.org/www-project-api-security/)
- [OWASP Top 10 - Broken Access Control](https://owasp.org/www-project-top-ten/)
- [CWE-602: Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html)
- [OWASP Cheat Sheet Series - Input Validation](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
