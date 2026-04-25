# Second-Order SQL Injection

## Overview

Second-order SQL injection happens in two acts. First, a payload is stored safely — typically through an ORM or a parameterized query, which escapes it correctly at insert time. Then, somewhere else in the application, a different code path reads that stored value and concatenates it into a raw SQL statement, where it finally executes as code. Input validation on the original write does not help; the problem is on the read path.

In this challenge, the product review endpoint stores a user-supplied author name through Prisma (safe), and the admin reviews dashboard later interpolates that author name into a raw `better-sqlite3` query (unsafe). Worse, the unsafe query is dispatched via `Database.exec()`, which runs multi-statement SQL — so an injected `; DROP TABLE …` actually executes.

## Why This Is Dangerous

- **Bypasses input-side defenses** — the malicious value looks identical to legitimate data when first stored.
- **Trust-by-origin fallacy** — developers assume "data from our own DB is safe", which is precisely the assumption the attack relies on.
- **Multi-statement execution** — `exec()` allows `;`-separated statements, turning what could have been a select into a destructive write.
- **Hard to test** — automated scanners that match request inputs to response outputs in a single round trip miss it entirely.

## Vulnerable Code

The write path is safe:

```typescript
const review = await prisma.review.create({
  data: {
    productId: id,
    content: content.trim(),
    author,
  },
});
```

The read path concatenates a stored value into raw SQL and executes it via `exec()`:

```typescript
const db = new Database(getDbPath());
const query = `
  SELECT
    r.id, r."productId", r.content, r.author, r."createdAt",
    p.name as "productName"
  FROM reviews r
  INNER JOIN products p ON r."productId" = p.id
  WHERE r.author = '${authorFilter}'
  ORDER BY r."createdAt" DESC
`;

db.exec(query);
```

`authorFilter` comes from a dropdown fed by the database itself, but the value originally came from a user-controlled review submission. Once interpolated into the SQL string, it is parsed as code; once handed to `exec()`, any number of statements parsed from that string will run.

## Secure Implementation

Treat _every_ value as untrusted, regardless of origin, and never let stored data become SQL syntax.

```typescript
const reviews = await prisma.review.findMany({
  where: { author: authorFilter },
  include: { product: { select: { name: true } } },
  orderBy: { createdAt: "desc" },
});
```

If the use case forces raw SQL, parameterize and use a single-statement API:

```typescript
const stmt = db.prepare(`
  SELECT r.id, r.author, r.content, p.name AS "productName"
  FROM reviews r
  INNER JOIN products p ON r."productId" = p.id
  WHERE r.author = ?
  ORDER BY r."createdAt" DESC
`);
const reviews = stmt.all(authorFilter);
```

Two further hardening steps for the same class of bug:

- Avoid multi-statement APIs (`exec`, `executeMany`) on user-touched paths. Use prepared single-statement primitives.
- Sanitize at output, not input. Even if it costs a layer of defense at write time, treat reads as adversarial — that is the only assumption that survives an unrelated insert path being added later.

## References

- [OWASP — Second-Order SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection#second-order-sql-injection)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
- [PortSwigger — Second-Order SQL Injection](https://portswigger.net/kb/issues/00100210_sql-injection-second-order)
