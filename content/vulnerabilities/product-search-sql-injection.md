# Product Search SQL Injection

## Overview

The product search endpoint (`GET /api/products/search`) builds a SQL query by interpolating the `q` query parameter directly into a `LIKE` clause, then runs the result with `prisma.$queryRawUnsafe`. Anything the caller puts in `q` becomes part of the query, so quotes, semicolons, and `UNION` clauses all change the meaning of the statement.

## Why This Is Dangerous

- **Cross-table data extraction** — `UNION SELECT` exposes data from any table the database role can read (users, orders, sessions, secrets).
- **Authorization bypass** — application-layer checks (per-user filters, hidden products) are enforced in the query that the injection rewrites.
- **Information disclosure** — error-based and time-based exfiltration work even when the response shape hides the data.
- **Lateral compromise** — leaked credentials, tokens, or environment values often unlock the rest of the system.

## Vulnerable Code

```typescript
const sqlQuery = `
  SELECT
    id,
    name,
    description,
    price,
    "imageUrl"
  FROM products
  WHERE name LIKE '%${query}%' OR description LIKE '%${query}%'
  ORDER BY name ASC
  LIMIT 50
`;

const results = await prisma.$queryRawUnsafe(sqlQuery);
```

`query` is interpolated into the SQL string with no escaping or parameterization, and `$queryRawUnsafe` runs the resulting string verbatim. The fact that `q` arrives via a search box does not constrain its content — the API has to defend itself.

## Secure Implementation

Use the Prisma query builder, which parameterizes inputs automatically:

```typescript
const results = await prisma.product.findMany({
  where: {
    OR: [
      { name: { contains: query, mode: "insensitive" } },
      { description: { contains: query, mode: "insensitive" } },
    ],
  },
  orderBy: { name: "asc" },
  take: 50,
});
```

If raw SQL is genuinely required (e.g. for full-text search features the ORM does not expose), use `prisma.$queryRaw` with tagged-template parameters, never `$queryRawUnsafe`:

```typescript
const pattern = `%${query}%`;
const results = await prisma.$queryRaw`
  SELECT id, name, description, price, "imageUrl"
  FROM products
  WHERE name ILIKE ${pattern} OR description ILIKE ${pattern}
  ORDER BY name ASC
  LIMIT 50
`;
```

The tagged-template form sends parameters out-of-band; the database never sees them as SQL syntax. Input validation, keyword denylists, and "WAF rules" are not substitutes — parameterized queries are the fix.

## References

- [OWASP Top 10 — A05:2025 Injection](https://owasp.org/Top10/2025/A05_2025-Injection/)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
- [PortSwigger — SQL Injection](https://portswigger.net/web-security/sql-injection)
