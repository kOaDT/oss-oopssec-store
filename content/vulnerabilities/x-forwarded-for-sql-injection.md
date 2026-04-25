# SQL Injection via `X-Forwarded-For`

## Overview

SQL injection is not just about query parameters and form fields — anything that ends up concatenated into a SQL string is a sink. HTTP headers, cookies, user-agents, and proxy-supplied values like `X-Forwarded-For` are all under attacker control unless a trusted reverse proxy strips and rewrites them.

In this challenge, the visitor-tracking endpoint builds a raw SQL `INSERT` from the `X-Forwarded-For` header value and runs it through `prisma.$queryRawUnsafe`. The header is never validated as an IP, never parameterized, and reachable on every page load.

## Why This Is Dangerous

- **Pre-auth, drive-by exploitation** — every page that triggers tracking exposes the database to anyone who can hit the URL.
- **Header values are fully attacker-controlled** — no proxy in this app strips or rewrites `X-Forwarded-For`, so the header arrives at the handler verbatim.
- **Compounding sinks** — the captured value is later rendered server-side; an injected payload can become stored XSS in the analytics dashboard.
- **Silent attack surface** — headers do not appear in URL logs, so naive monitoring misses the payload entirely.

## Vulnerable Code

```typescript
const forwardedFor = request.headers.get("x-forwarded-for");
const ip = forwardedFor || request.headers.get("x-real-ip") || "unknown";

const query = `
  INSERT INTO visitor_logs (id, ip, userAgent, path, sessionId, createdAt)
  VALUES ('${id}', '${ip}', '${userAgent.replace(/'/g, "''")}', '${visitPath.replace(/'/g, "''")}', ${visitorSessionId ? `'${visitorSessionId}'` : "NULL"}, datetime('now'))
`;

await prisma.$queryRawUnsafe(query);
```

The `userAgent` and `visitPath` columns receive a quote-doubling pass; the `ip` column does not. Even when escaping is applied, hand-rolled escaping is the wrong primitive — it is fragile, format-specific, and silently differs between databases. Parameterized queries are the correct primitive everywhere.

## Secure Implementation

Use the ORM, which parameterizes everything by default:

```typescript
await prisma.visitorLog.create({
  data: {
    ip,
    userAgent,
    path: visitPath,
    sessionId: visitorSessionId,
  },
});
```

If raw SQL is genuinely required, switch to a parameterized form (tagged templates in Prisma, prepared statements in `better-sqlite3` / `pg`):

```typescript
await prisma.$executeRaw`
  INSERT INTO visitor_logs (id, ip, "userAgent", path, "sessionId", "createdAt")
  VALUES (${id}, ${ip}, ${userAgent}, ${visitPath}, ${visitorSessionId}, NOW())
`;
```

Defense in depth around the same input:

- **Validate the header against an IP grammar** (`net.isIP` in Node, or `ipaddr.js`) and replace anything that does not parse with `"unknown"`.
- **Rewrite at the edge.** A trusted reverse proxy or CDN should overwrite `X-Forwarded-For` with values it controls, not append to whatever the client sent.
- **Render output safely.** When tracking values are displayed in admin dashboards, render them through React's default escaping — never `dangerouslySetInnerHTML`.

## References

- [OWASP Top 10 — A03:2021 Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
- [MDN — `X-Forwarded-For`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For)
- [PortSwigger — SQL Injection](https://portswigger.net/web-security/sql-injection)
