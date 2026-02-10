---
author: kOaDT
authorGithubUrl: https://github.com/kOaDT
authorGithubAvatar: https://avatars.githubusercontent.com/u/17499022?v=4
pubDatetime: 2026-01-31T20:25:00Z
title: "Broken Object Level Authorization: Accessing Private Wishlists"
slug: bola-wishlist-access
draft: false
tags:
  - writeup
  - bola
  - authorization
  - ctf
description: Exploiting a Broken Object Level Authorization vulnerability in OopsSec Store's wishlist feature to access other users' private wishlists and retrieve sensitive internal data.
---

This writeup demonstrates the exploitation of a Broken Object Level Authorization (BOLA) vulnerability in OopsSec Store's wishlist feature. The API correctly authenticates users but fails to enforce object-level ownership checks, allowing any authenticated user to access arbitrary wishlists by manipulating the identifier in API requests.

## Table of contents

## Lab setup

The lab requires Node.js. From an empty directory, run the following commands:

```bash
npx create-oss-store oss-store
cd oss-store
npm start
```

Once Next.js has started, the application is accessible at `http://localhost:3000`.

## Vulnerability overview

The OopsSec Store allows users to create private wishlists to save products for later purchase. Each wishlist is scoped to the authenticated user in the UI: the frontend only displays the current user's wishlists.

However, the backend API endpoint `GET /api/wishlists/[id]` accepts any wishlist identifier and returns its full contents without verifying that the requesting user owns the resource. This is a textbook BOLA vulnerability: the server trusts the client-supplied object identifier without performing an authorization check.

The vulnerability is compounded by the existence of an internal admin wishlist (`wl-internal-001`) that contains a sensitive note with a flag value, representing business-critical information that should never be accessible to regular users.

## Exploitation

### Step 1: Authenticating as a standard user

Navigate to the login page and authenticate with the test credentials:

- Email: `alice@example.com`
- Password: `iloveduck`

### Step 2: Using the wishlist feature

Navigate to the Wishlists page via the header navigation. Create a new wishlist or browse an existing one. Observe normal functionality: the page displays only your own wishlists.

### Step 3: Observing API behavior

Open the browser developer tools (Network tab) and click "View Wishlist" on one of your wishlists. Observe the API request:

```
GET /api/wishlists/wl-alice-001
Cookie: authToken=<your-jwt-token>
```

The response includes the full wishlist data: name, items, owner email, and notes.

### Step 4: Identifying the attack vector

The wishlist identifier (`wl-alice-001`) appears directly in the API URL path. Key observations:

- The ID format suggests a naming convention: `wl-{username}-{number}`
- The API accepts the ID as a user-controlled input
- The response includes data that should be private (owner email, notes)

The question becomes: does the API enforce ownership verification, or does it return any wishlist to any authenticated user?

### Step 5: Accessing unauthorized wishlists

Modify the API request to target a different wishlist. Using curl or the browser console:

```bash
curl -b "authToken=<your-jwt-token>" \
  http://localhost:3000/api/wishlists/wl-internal-001
```

Or in the browser console:

```javascript
const res = await fetch("/api/wishlists/wl-internal-001", {
  credentials: "include",
});
const data = await res.json();
console.log(data);
```

The API returns the admin's internal wishlist, including all items, the owner email (`admin@oss.com`), and the `note` field containing the flag.

### Step 6: Retrieving the flag

The flag is present in the API response:

```
OSS{brok3n_0bj3ct_l3v3l_4uth0r1z4t10n}
```

![Postman](../../assets/images/bola-wishlist-access/postman.png)

This confirms successful exploitation of the BOLA vulnerability.

## Vulnerable code analysis

The vulnerability exists in the `GET` handler of `/api/wishlists/[id]/route.ts`. The code authenticates the user but does not verify ownership before returning the wishlist data:

```typescript
const user = await getAuthenticatedUser(request);
if (!user) {
  return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
}

const wishlist = await prisma.wishlist.findUnique({
  where: { id },
  include: { items: { include: { product: true } } },
});

// Missing: ownership verification
// wishlist.userId is never compared to user.id
return NextResponse.json(wishlist);
```

The endpoint correctly rejects unauthenticated requests (401), creating the illusion of security. But being authenticated does not mean being authorized to access a specific resource. The fundamental check `wishlist.userId !== user.id` is absent from the read path.

Notably, the `DELETE` handler on the same endpoint correctly implements the ownership check, making the inconsistency a realistic developer oversight.

## Remediation

### Enforcing ownership verification

The API must verify that the authenticated user owns the requested wishlist before returning data:

```typescript
const wishlist = await prisma.wishlist.findUnique({
  where: { id },
});

if (!wishlist) {
  return NextResponse.json({ error: "Wishlist not found" }, { status: 404 });
}

if (wishlist.userId !== user.id) {
  return NextResponse.json({ error: "Forbidden" }, { status: 403 });
}
```

### Query-level ownership filtering

An alternative approach incorporates the ownership constraint into the database query:

```typescript
const wishlist = await prisma.wishlist.findFirst({
  where: {
    id,
    userId: user.id,
  },
});

if (!wishlist) {
  return NextResponse.json({ error: "Wishlist not found" }, { status: 404 });
}
```

This pattern prevents information leakage about the existence of other users' resources and eliminates the possibility of returning unauthorized data even if a logic error occurs downstream.

### Consistent authorization patterns

The most common cause of BOLA vulnerabilities is inconsistent application of authorization checks across CRUD operations. A resource that enforces ownership for `DELETE` but not for `GET` represents a pattern that automated security tools may miss but attackers will find. Authorization logic should be centralized or applied uniformly to all operations on a resource.
