# SQL Injection

## Overview

SQL injection happens when an application builds SQL queries by concatenating user-controlled input directly into the query string. Without parameterization, the database has no way to tell the difference between data and SQL syntax, so any user input that contains SQL metacharacters can change the meaning of the query.

In this challenge, the order search endpoint takes a `status` filter from the request body and inlines it into a raw SQL query.

## Why This Is Dangerous

- **Query manipulation** — attackers can break out of the intended query structure with quotes, semicolons, or `UNION` clauses.
- **Data extraction** — `UNION SELECT` lets an attacker pull arbitrary columns from any table the database user can read.
- **Authorization bypass** — application-level checks (like "users can only see their own orders") are bypassed because the injection rewrites the query itself.
- **Information disclosure** — credentials, tokens, and other secrets stored in the database become reachable.

## Vulnerable Code

```typescript
const statusFilter =
  status && typeof status === "string" ? `AND o.status = '${status}'` : "";

const query = `
  SELECT
    o.id, o.total, o.status, o."userId",
    a.street, a.city, a.state, a."zipCode", a.country
  FROM orders o
  INNER JOIN addresses a ON o."addressId" = a.id
  WHERE o."userId" = '${user.id}' ${statusFilter}
  ORDER BY o.id DESC
`;

const results = await prisma.$queryRawUnsafe(query);
```

The `status` parameter is interpolated into the query string with no escaping or parameterization. `prisma.$queryRawUnsafe` runs the resulting string as-is. Even though the frontend dropdown only ever sends a fixed set of values, the API still trusts whatever arrives in the request body.

## Secure Implementation

Use the Prisma query builder, which parameterizes inputs automatically:

```typescript
const results = await prisma.order.findMany({
  where: {
    userId: user.id,
    ...(status ? { status } : {}),
  },
  include: {
    address: true,
  },
});
```

If raw SQL is genuinely required, use prepared statements with placeholders instead of string interpolation:

```typescript
const results = await prisma.$queryRaw`
  SELECT o.id, o.total, o.status
  FROM orders o
  WHERE o."userId" = ${user.id}
    AND o.status = ${status}
`;
```

The tagged-template form (`$queryRaw`) parameterizes the interpolated values. The unsafe form (`$queryRawUnsafe`) does not — avoid it unless you control every character of the input.

Input validation and escaping are not a substitute. Parameterized queries are the fix.

## References

- [OWASP Top 10 - Injection](https://owasp.org/Top10/2025/A05_2025-Injection/)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
- [PortSwigger Web Security Academy - SQL Injection](https://portswigger.net/web-security/sql-injection)
