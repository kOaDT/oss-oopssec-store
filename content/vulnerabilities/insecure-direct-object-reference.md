# Insecure Direct Object Reference (IDOR)

## Overview

This vulnerability demonstrates a critical security flaw where the application does not properly verify that a user has authorization to access a specific resource. In this case, users can access order details belonging to other users by simply modifying the order ID in the URL, without any proper authorization checks.

## Why This Is Dangerous

### Missing Authorization Checks

When an application allows direct access to resources based on predictable or guessable identifiers without verifying ownership, it creates a fundamental security vulnerability:

1. **Predictable resource identifiers** - Order IDs follow a sequential pattern (ORD-001, ORD-002, etc.) making them easy to guess
2. **No ownership verification** - The API returns order details regardless of who owns the order
3. **Information disclosure** - Attackers can access sensitive information like customer names, emails, and delivery addresses
4. **Privacy violation** - Users can view other users' personal information and order history

### What This Means

**Always verify resource ownership before returning data.** The server must:

- Check that the authenticated user owns the requested resource
- Return 403 Forbidden if the user tries to access resources they don't own
- Use unpredictable, non-sequential identifiers when possible
- Implement proper access control at the API level, not just the UI level

## The Vulnerability

In this application, the order details endpoint (`/api/orders/[id]`) retrieves order information without properly verifying that the authenticated user owns the requested order. The server:

1. Authenticates the user (checks if they're logged in)
2. Retrieves the order by ID
3. Returns order details including customer information and delivery address
4. Does not verify that `order.userId` matches the authenticated user's ID

Additionally, order IDs use a predictable sequential format (ORD-001, ORD-002, ORD-003), making it trivial to enumerate and access other users' orders.

## Exploitation

### How to Retrieve the Flag

To retrieve the flag `OSS{1ns3cur3_d1r3ct_0bj3ct_r3f3r3nc3}`, you need to exploit the IDOR vulnerability:

**Exploitation Steps:**

1. Log in as Alice (alice@example.com / iloveduck)
2. Navigate to the order confirmation page with your own order ID (if you have one)
3. Observe the order ID format (e.g., ORD-004)
4. Modify the URL to access Bob's orders by changing the order ID:
   - Try `ORD-001`, `ORD-002`, or `ORD-003`
5. The page will display Bob's order details including:
   - Customer name and email
   - Delivery address
   - Order total and status
6. The flag `OSS{1ns3cur3_d1r3ct_0bj3ct_r3f3r3nc3}` will be displayed at the top of the page

### Secure Implementation

```typescript
// ❌ VULNERABLE - No ownership check
const order = await prisma.order.findUnique({
  where: { id },
});

if (!order) {
  return NextResponse.json({ error: "Order not found" }, { status: 404 });
}

return NextResponse.json({
  id: order.id,
  total: order.total,
  status: order.status,
});

// ✅ SECURE - Verifies ownership
const order = await prisma.order.findUnique({
  where: { id },
});

if (!order) {
  return NextResponse.json({ error: "Order not found" }, { status: 404 });
}

if (order.userId !== user.id) {
  return NextResponse.json({ error: "Forbidden" }, { status: 403 });
}

return NextResponse.json({
  id: order.id,
  total: order.total,
  status: order.status,
});
```

## References

- [OWASP API Security Top 10 - Broken Object Level Authorization](https://owasp.org/www-project-api-security/)
- [OWASP Top 10 - Broken Access Control](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
- [OWASP Cheat Sheet Series - Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
