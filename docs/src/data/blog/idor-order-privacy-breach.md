---
author: kOaDT
authorGithubUrl: https://github.com/kOaDT
authorGithubAvatar: https://avatars.githubusercontent.com/u/17499022?v=4
pubDatetime: 2026-01-20T10:00:00Z
title: "Insecure Direct Object Reference: Unauthorized Order Access"
slug: idor-order-privacy-breach
draft: false
tags:
  - writeup
  - idor
  - ctf
description: Exploiting an insecure direct object reference vulnerability in OopsSec Store to access other customers' order details.
---

This writeup demonstrates the exploitation of an insecure direct object reference (IDOR) vulnerability in OopsSec Store's order confirmation feature. The vulnerability allows any authenticated user to access arbitrary order records by modifying the order identifier in the URL, exposing personal information belonging to other customers.

## Table of contents

## Lab setup

The lab requires Node.js. From an empty directory, run the following commands:

```bash
npx create-oss-store oss-store
cd oss-store
npm run dev
```

Once Next.js has started, the application is accessible at `http://localhost:3000`.

## Vulnerability overview

After placing an order, users are redirected to an order confirmation page with a URL structure such as `/orders/ORD-004`. The order identifier is human-readable, sequential, and directly references the database record.

The vulnerability arises from two compounding issues:

1. **Missing authorization checks**: The backend retrieves orders by identifier without verifying ownership
2. **Predictable identifiers**: Sequential order IDs enable trivial enumeration

When combined, these flaws allow an attacker to access any order in the system by guessing or iterating through valid identifiers.

## Exploitation

### Step 1: Authenticating as a standard user

Navigate to the login page and authenticate with the test credentials:

- Email: `alice@example.com`
- Password: `iloveduck`

![Homepage](../../assets/images/idor-order-privacy-breach/homepage.webp)

### Step 2: Creating an order

Browse the product catalog and add any item to the cart. Proceed through the checkout flow to completion.

Upon successful order placement, the application redirects to the order confirmation page. The URL follows the pattern:

```
http://localhost:3000/orders/ORD-004
```

The exact order number depends on existing database state, but the sequential pattern is consistent.

![Order confirmation page showing user's order](../../assets/images/idor-order-privacy-breach/order-confirmation.webp)

### Step 3: Identifying the attack vector

The order identifier exhibits characteristics that indicate potential IDOR vulnerability:

- **Human-readable format**: The `ORD-` prefix followed by a numeric sequence suggests internal record numbering
- **Sequential allocation**: If the current order is `ORD-004`, previous orders (`ORD-001`, `ORD-002`, `ORD-003`) likely exist
- **Direct URL exposure**: The identifier appears directly in the URL path, accessible to user modification

### Step 4: Accessing unauthorized orders

Modify the URL to reference a different order identifier:

```
http://localhost:3000/orders/ORD-001
```

The page loads successfully, displaying order details that belong to a different user.

![Order page showing another customer's data](../../assets/images/idor-order-privacy-breach/unauthorized-order-access.webp)

The exposed information includes:

- Customer name
- Email address
- Delivery address
- Order contents and pricing

### Step 5: Retrieving the flag

The flag is displayed at the top of the order confirmation page:

```
OSS{1ns3cur3_d1r3ct_0bj3ct_r3f3r3nc3}
```

This confirms successful exploitation of the IDOR vulnerability.

## Vulnerable code analysis

The vulnerability exists because the backend retrieves orders based solely on the provided identifier without validating ownership. The API endpoint accepts the order ID from the URL, queries the database, and returns the result regardless of which user made the request.

The authorization logic is absent:

```typescript
const order = await prisma.order.findUnique({
  where: { id },
});

// Missing: ownership verification
// The order is returned to any authenticated user
```

Authentication verifies that a user is logged in, but authorization—confirming that the user has permission to access the specific resource—is not enforced.

## Remediation

### Enforcing ownership verification

The API must verify that the authenticated user owns the requested resource before returning data:

```typescript
const order = await prisma.order.findUnique({
  where: { id },
});

if (!order) {
  return NextResponse.json({ error: "Order not found" }, { status: 404 });
}

if (order.userId !== user.id) {
  return NextResponse.json({ error: "Forbidden" }, { status: 403 });
}
```

This check must execute on the server. Client-side routing or UI-level restrictions provide no security against direct API requests.

### Reducing identifier predictability

While not a substitute for proper authorization, using non-sequential identifiers raises the difficulty of enumeration attacks:

- **UUIDs**: Replace sequential IDs with universally unique identifiers (e.g., `550e8400-e29b-41d4-a716-446655440000`)
- **Opaque tokens**: Generate random, unguessable strings for external references
- **Indirect references**: Map user-facing identifiers to internal IDs through a separate lookup table

Identifier obfuscation adds defense in depth but does not address the root cause. Authorization checks remain the primary control.

### Query-level ownership filtering

An alternative approach incorporates ownership into the database query itself:

```typescript
const order = await prisma.order.findFirst({
  where: {
    id,
    userId: user.id,
  },
});

if (!order) {
  return NextResponse.json({ error: "Order not found" }, { status: 404 });
}
```

This pattern ensures that users can only retrieve records they own. The query returns `null` for orders belonging to other users, treating them identically to non-existent orders.
