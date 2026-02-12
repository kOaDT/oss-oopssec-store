# Second-Order SQL Injection

## Overview

This vulnerability demonstrates a second-order (stored) SQL injection attack. Unlike traditional SQL injection where the malicious payload is executed immediately upon submission, second-order injection occurs when a payload is first safely stored in the database and then later used unsafely in a different context. In this case, a malicious author name submitted via a product review is stored safely through Prisma ORM, but is later interpolated directly into a raw SQL query when an admin filters reviews by author on the moderation panel.

## Why This Is Dangerous

### The False Sense of Security

Second-order SQL injection is particularly insidious because:

1. **Deferred execution** - The payload is stored safely during insertion, making it invisible to input-level defenses
2. **Different context** - The vulnerability exists in a completely different part of the application from where the data was entered
3. **Trusted data assumption** - Developers often assume data from their own database is safe and does not need sanitization
4. **Difficult to detect** - Automated scanners that test input/output pairs in a single request often miss second-order vulnerabilities
5. **Destructive potential** - A stored `DROP TABLE` payload could wipe out entire tables when triggered by an admin action

## The Vulnerability

In this application, the attack chain involves two separate operations:

### Step 1: Safe Storage (Review Submission)

The review API accepts a custom author field and stores it via Prisma ORM (which uses parameterized queries internally):

```typescript
// /api/products/[id]/reviews - SAFE insertion
const review = await prisma.review.create({
  data: {
    productId: id,
    content: content.trim(),
    author, // User-controlled, but stored safely via parameterized query
  },
});
```

### Step 2: Unsafe Retrieval (Admin Filter)

The admin reviews API fetches reviews filtered by author using raw SQL with string interpolation:

```typescript
// /api/admin/reviews - VULNERABLE query using raw SQLite driver
const db = new Database(getDbPath());
const query = `
  SELECT
    r.id,
    r."productId",
    r.content,
    r.author,
    r."createdAt",
    p.name as "productName"
  FROM reviews r
  INNER JOIN products p ON r."productId" = p.id
  WHERE r.author = '${authorFilter}'
  ORDER BY r."createdAt" DESC
`;

db.exec(query); // exec() supports multi-statement execution
```

The `authorFilter` value comes from the dropdown, which is populated from the database. The developer assumed these values were safe because they originated from the application's own database. The use of `better-sqlite3`'s `exec()` method is particularly dangerous because it supports multi-statement queries, meaning a `DROP TABLE` or `DELETE FROM` statement injected via a semicolon will actually execute.

## Exploitation

### How to Retrieve the Flag

**Step 1: Submit a review with a destructive SQL payload as the display name**

Log in or use any account. Submit a review on any product, setting the "Display name" field to a destructive SQL payload:

```
'; DROP TABLE reviews; --
```

The review is stored safely — no SQL execution happens at this point.

**Step 2: Gain admin access**

Use an existing vulnerability (mass assignment during signup or JWT forgery with the weak secret) to obtain admin privileges.

**Step 3: Trigger the injection**

Navigate to `/admin/reviews`. The malicious author name appears in the "Filter by author" dropdown. Select it. The backend interpolates this stored value into raw SQL and executes it via `better-sqlite3`'s `exec()`, which supports multi-statement queries. The `DROP TABLE reviews` statement actually executes, destroying the reviews table.

The backend detects the SQL injection attempt and returns the flag in the response, which is displayed on the page.

### Secure Implementation

```typescript
// VULNERABLE - Interpolating stored values into raw SQL with multi-statement support
const db = new Database(getDbPath());
const query = `SELECT ... FROM reviews WHERE author = '${authorFilter}'`;
db.exec(query);

// SECURE - Use Prisma's parameterized queries
const reviews = await prisma.review.findMany({
  where: {
    author: authorFilter,
  },
  include: {
    product: {
      select: { name: true },
    },
  },
  orderBy: { createdAt: "desc" },
});
```

**Key lesson:** Never assume data from your own database is safe for use in raw SQL queries. Always use parameterized queries regardless of the data source.

## References

- [OWASP - Second Order SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection#second-order-sql-injection)
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
- [PortSwigger - Second-Order SQL Injection](https://portswigger.net/kb/issues/00100210_sql-injection-second-order)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
