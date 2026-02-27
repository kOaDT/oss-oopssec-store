---
author: kOaDT
authorGithubUrl: https://github.com/kOaDT
authorGithubAvatar: https://avatars.githubusercontent.com/u/17499022?v=4
pubDatetime: 2026-02-12T21:48:00Z
title: "Second-Order SQL Injection: When Trusted Data Turns Hostile"
slug: second-order-sql-injection
draft: false
tags:
  - writeup
  - sql-injection
  - second-order
  - ctf
description: How a crafted display name stored through a product review becomes a SQL injection payload when an admin filters reviews on the moderation panel.
---

This writeup walks through a second-order SQL injection in OopsSec Store's review moderation feature. The twist compared to a classic SQL injection: the payload doesn't execute when it's submitted. It sits harmlessly in the database until the application feeds it into a different, unparameterized query.

## Table of contents

## Lab setup

The lab requires Node.js. From an empty directory, run the following commands:

```bash
npx create-oss-store oss-store
cd oss-store
npm start
```

Once Next.js has started, the application is accessible at `http://localhost:3000`.

## Target identification

The application lets users submit product reviews with a customizable "Display name" field. Instead of defaulting to their email address, users pick how their name shows up on reviews.

![Page Product - Reviews](../../assets/images/second-order-sql-injection/reviews.png)

The admin panel has a "Review Moderation" section at `/admin/reviews` where admins can view and filter all reviews by author. The filter is a dropdown populated with distinct author names from the database.

![Admin interface](../../assets/images/second-order-sql-injection/admin.png)

## Understanding second-order injection

In a classic (first-order) SQL injection, the payload executes at the point of input. In a second-order attack, the malicious input is stored safely first and only executes later when the application reuses it in a different, unsafe context.

The developer mistake: assuming that data from your own database is trustworthy and doesn't need parameterization.

## Exploitation

### Step 1: Store the payload

Log in to the application with any account (e.g., `alice@example.com` / `iloveduck`). Navigate to any product page and submit a review. In the "Display name" field, enter a destructive SQL payload:

```
'; DROP TABLE reviews; --
```

Write any content in the review body and submit. The review is stored safely via Prisma ORM, no SQL is executed at this point. The payload is just an ordinary string in the database.

![Exploit](../../assets/images/second-order-sql-injection/exploit.png)

### Step 2: Gain admin access

To access the admin panel, you need admin privileges. You can get there through other vulnerabilities in the lab (Mass Assignment, JWT forgery, SQL Injection with Weak MD5, etc).

### Step 3: Trigger the injection

Navigate to `/admin/reviews`. The review moderation panel displays all reviews in a table with a "Filter by author" dropdown.

![Admin Interface with SQL Injection](../../assets/images/second-order-sql-injection/admin-with-sql.png)

The dropdown includes the malicious payload stored in Step 1 as one of the author values. Select it.

### Step 4: Retrieve the flag

When the filter is applied, the backend builds a raw SQL query by interpolating the stored author value:

```typescript
const query = `
  SELECT ...
  FROM reviews r
  INNER JOIN products p ON r."productId" = p.id
  WHERE r.author = '${authorFilter}'
  ORDER BY r."createdAt" DESC
`;
```

The stored payload `'; DROP TABLE reviews; --` gets interpolated into:

```sql
WHERE r.author = ''; DROP TABLE reviews; --'
```

The backend uses `better-sqlite3`'s `exec()` method, which supports multi-statement queries. So the `DROP TABLE reviews` statement actually runs and wipes the entire reviews table. The backend detects the SQL injection attempt and returns the flag in the response.

![Flag](../../assets/images/second-order-sql-injection/flag-sql.png)

## Vulnerable code analysis

The vulnerability is in the admin reviews API endpoint at `/api/admin/reviews`:

```typescript
// Reviews are stored safely via Prisma ORM (parameterized)
const review = await prisma.review.create({
  data: { productId: id, content, author }, // Safe
});

// But later reused unsafely via raw SQLite driver with multi-statement support
const db = new Database(getDbPath());
const query = `
  SELECT r.id, r.content, r.author, ...
  FROM reviews r
  WHERE r.author = '${authorFilter}'   // VULNERABLE
`;
db.exec(query); // exec() runs ALL statements, including DROP TABLE
```

The developer trusted the author value because it came from the application's own database dropdown, not directly from user input. Using `exec()` instead of `prepare()` makes it worse: `exec()` allows multi-statement execution, so a `DROP TABLE` slipped into the query string will actually run.

## Remediation

Replace the raw SQL query with Prisma's parameterized query builder:

```typescript
// SECURE - Use Prisma's built-in parameterization
const reviews = await prisma.review.findMany({
  where: { author: authorFilter },
  include: { product: { select: { name: true } } },
  orderBy: { createdAt: "desc" },
});
```

The root issue is treating database-sourced data as safe. It isn't. Parameterize every query regardless of where the data comes from. For filter dropdowns like this one, an allowlist of valid values is even better since the set of authors is known ahead of time.
