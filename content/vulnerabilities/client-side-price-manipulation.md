# Client-Side Price Manipulation

## Overview

The order creation endpoint accepts the cart total from the client and persists it without recomputing it from the authoritative product prices. Anything sent from the browser is under the user's control, so trusting a client-supplied total turns checkout into a self-service discount mechanism.

In this challenge, `POST /api/orders` reads `total` from the request body, validates only that it is a positive number, and writes that value straight into the new order.

## Why This Is Dangerous

- **Direct financial loss** — the buyer pays whatever total they choose to send.
- **Discount and tax bypass** — server-side promotions, taxes, and shipping rules are silently overridden.
- **Inventory and accounting drift** — orders ship with totals that do not match the product prices on file.
- **Cascading abuse** — manipulated totals can corrupt revenue reports, fraud detection, and loyalty programs that read from order data.

## Vulnerable Code

```typescript
export const POST = withAuth(async (request: NextRequest, _context, user) => {
  const body = await request.json();
  const { total } = body;

  if (!total || typeof total !== "number" || total <= 0) {
    return NextResponse.json(
      { error: "Valid total is required" },
      { status: 400 }
    );
  }

  // ... cart loaded, but `total` from the request is what gets stored
  const order = await prisma.order.create({
    data: {
      userId: user.id,
      addressId: userWithAddress.addressId,
      total: total,
      status: "PENDING",
    },
  });
});
```

The endpoint loads the user's cart, but uses the client-supplied `total` rather than the value computed from the cart's products.

## Secure Implementation

Recompute the total on the server from the authoritative source — the user's cart and the current product prices — and ignore whatever the client sent:

```typescript
const cart = await prisma.cart.findFirst({
  where: { userId: user.id },
  include: { cartItems: { include: { product: true } } },
});

if (!cart || cart.cartItems.length === 0) {
  return NextResponse.json({ error: "Cart is empty" }, { status: 400 });
}

const total = cart.cartItems.reduce(
  (sum, item) => sum + item.product.price * item.quantity,
  0
);

const order = await prisma.order.create({
  data: { userId: user.id, addressId, total, status: "PENDING" },
});
```

Coupons, taxes, and shipping must be applied on the server too, against trusted rules. Anything financial that comes from the client is a hint at most — never an instruction.

## References

- [OWASP API Security Top 10 — API6:2023 Unrestricted Access to Sensitive Business Flows](https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/)
- [OWASP Top 10 — A04:2021 Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)
- [CWE-602: Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html)
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
