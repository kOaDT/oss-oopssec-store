# Product Search SQL Injection

## Overview

This vulnerability demonstrates a critical security flaw where user input from a product search feature is directly concatenated into SQL queries without proper sanitization or parameterization. The search functionality allows users to find products by name or description, but the search query parameter is inserted directly into the SQL query string, enabling attackers to manipulate the query structure and extract unauthorized data.

## Why This Is Dangerous

### Direct String Concatenation in SQL Queries

When an application constructs SQL queries by directly concatenating user input into the query string, it creates a fundamental security vulnerability:

1. **Query manipulation** - Attackers can break out of the intended query structure using SQL syntax
2. **Data extraction** - Malicious queries can retrieve data from any table the database user has access to
3. **Bypass authorization** - SQL injection can bypass application-level access controls
4. **Information disclosure** - Attackers can extract sensitive information including user credentials and other confidential data

## The Vulnerability

In this application, the product search endpoint (`/api/products/search`) constructs SQL queries by directly concatenating the user-provided search query into the query string. The search parameter is passed via the `q` query parameter:

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

The `query` parameter is inserted directly into the SQL query without any sanitization or parameterization. This allows an attacker to:

1. Break out of the intended query structure using SQL syntax (single quotes, semicolons, etc.)
2. Use UNION SELECT to retrieve data from other tables
3. Extract sensitive information from the database

## Exploitation

### How to Retrieve the Flag

To retrieve the flag `OSS{pr0duct_s34rch_sql_1nj3ct10n}`, you need to exploit the SQL injection vulnerability:

**Exploitation Steps:**

1. Navigate to the Product Search page by clicking the "Search" link in the header
2. Enter a SQL injection payload in the search box, such as:
   - `' UNION SELECT 1,2,3,4,5--`
   - `DELIVERED' UNION SELECT id, email, password, role, addressId FROM users--`
3. Submit the search
4. The application detects the SQL injection attempt and automatically returns the flag in the response

**Using curl:**

```bash
curl "http://localhost:3000/api/products/search?q=DELIVERED%27%20UNION%20SELECT%20id%2C%20email%2C%20password%2C%20role%2C%20addressId%20FROM%20users--"
```

### Secure Implementation

```typescript
// ❌ VULNERABLE - Direct string concatenation
const sqlQuery = `
  SELECT * FROM products
  WHERE name LIKE '%${query}%'
`;
const results = await prisma.$queryRawUnsafe(sqlQuery);

// ✅ SECURE - Parameterized query with Prisma
const results = await prisma.product.findMany({
  where: {
    OR: [
      { name: { contains: query, mode: "insensitive" } },
      { description: { contains: query, mode: "insensitive" } },
    ],
  },
});
```

## References

- [OWASP Top 10 - Injection](https://owasp.org/Top10/2025/A05_2025-Injection/)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
- [PortSwigger Web Security Academy - SQL Injection](https://portswigger.net/web-security/sql-injection)

## Flag

The flag for this vulnerability is: **OSS{pr0duct_s34rch_sql_1nj3ct10n}**

The flag is automatically returned by the API when a SQL injection attempt is detected in the product search feature. Any SQL injection payload (containing keywords like `UNION`, `SELECT`, `OR 1=1`, `--`, etc.) will trigger the detection and return the flag. The application specifically blocks direct access to the `flags` table through SQL injection to prevent retrieving all flags at once.
