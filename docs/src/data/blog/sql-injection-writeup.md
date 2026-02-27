---
author: kOaDT
authorGithubUrl: https://github.com/kOaDT
authorGithubAvatar: https://avatars.githubusercontent.com/u/17499022?v=4
pubDatetime: 2026-01-10T10:00:00Z
title: "SQL Injection: From Dropdown to Database Dump"
slug: sql-injection-writeup
draft: false
tags:
  - writeup
  - sql-injection
  - ctf
description: How a simple order status filter can be exploited to extract every user's credentials from the database.
---

The order filtering page on OopsSec Store takes a status string from a dropdown and drops it straight into a SQL query. No parameterization, no escaping. That's enough to dump the entire `users` table: emails, passwords, roles.

## Table of contents

## Lab setup

The lab requires Node.js. From an empty directory:

```bash
npx create-oss-store oss-store
cd oss-store
npm start
```

Head to `http://localhost:3000`.

## Target identification

There's a "My Orders" page where you can filter orders by status (`PENDING`, `SHIPPED`, `DELIVERED`, etc.). Pick a status from the dropdown and the frontend sends a POST to `/api/orders/search`:

```json
{
  "status": "DELIVERED"
}
```

That `status` value gets dropped straight into a SQL query on the backend. No sanitization.

## Exploitation

### Step 1: Log in

Use the test credentials on the login page:

- Email: `alice@example.com`
- Password: `iloveduck`

![Login page with Alice credentials](../../assets/images/sql-injection/login.webp)

### Step 2: Find the vulnerable endpoint

After logging in, go to `http://localhost:3000/orders/search`. This is the order search page with the status dropdown.

![My Orders page](../../assets/images/sql-injection/orders.webp)

### Step 3: Intercept the request

Open DevTools, go to the Network tab. Use the dropdown to trigger a POST to `/api/orders/search`.

![Network tab showing the POST request](../../assets/images/sql-injection/network.webp)

Copy the request into Burp Suite or Postman so you can edit the body.

### Step 4: Craft the payload

This is a UNION-based injection. The idea: close the original query's string literal, tack on a `UNION SELECT` that pulls from the `users` table, and comment out the rest. Replace the body with:

```json
{
  "status": "DELIVERED' UNION SELECT id, email, password, role, addressId, id, email, password, role FROM users --"
}
```

Breaking it down:

1. The single quote (`'`) closes the string literal in the original query
2. `UNION SELECT` appends a second result set from `users`
3. The column count and types have to match the original query -- hence the repeated columns
4. `--` comments out whatever comes after

### Step 5: Get the data

Send it. The server runs the injected SQL without flinching.

![Postman](../../assets/images/sql-injection/postman.webp)

The response mixes user data in with the order results. You also get the flag:

```json
{
  "flag": "OSS{sql_1nj3ct10n_vuln3r4b1l1ty}"
}
```

![Response containing the flag](../../assets/images/sql-injection/flag.webp)

## Vulnerable code analysis

Here's what the backend does with your input:

```ts
const statusFilter =
  status && typeof status === "string" ? `AND o.status = '${status}'` : "";

const query = `
  SELECT ...
  FROM orders o
  WHERE o."userId" = '${user.id}' ${statusFilter}
`;
```

The code expects something like `DELIVERED`. It gets a UNION SELECT instead.

## Remediation

Use parameterized queries. With Prisma:

```ts
const results = await prisma.order.findMany({
  where: {
    userId: user.id,
    status: status,
  },
});
```

Prisma parameterizes `status` automatically, so injected SQL never gets executed. If you need raw SQL, use prepared statements with placeholders instead of string interpolation.

Don't rely on input validation or escaping to stop SQL injection. Parameterized queries are the fix.
