# Next.js Middleware Authorization Bypass (CVE-2025-29927)

## Overview

This vulnerability allows attackers to completely bypass Next.js middleware-based authentication and authorization by sending a specially crafted HTTP header. The `x-middleware-subrequest` header is used internally by Next.js to prevent infinite middleware recursion, but versions prior to 15.2.3 do not validate that this header originates from an internal request.

## Root Cause

The vulnerability stems from:

1. **Trusted Internal Header**: Next.js uses `x-middleware-subrequest` to track middleware execution and prevent recursive loops
2. **No Origin Validation**: The framework does not verify that this header comes from an internal subrequest rather than an external client
3. **Middleware Skip Logic**: When the header value matches the middleware module name repeated to satisfy the recursion depth threshold, Next.js skips middleware execution entirely
4. **Single Layer of Defense**: Applications that rely solely on middleware for access control have no fallback when middleware is bypassed

## Impact

This vulnerability allows attackers to:

- Bypass all middleware-based authentication checks
- Access protected routes without valid credentials
- Reach internal dashboards, admin panels, and sensitive endpoints
- Circumvent rate limiting, geo-blocking, or any other middleware-enforced policy

## Exploitation

### How to Retrieve the Flag

To retrieve the flag `OSS{m1ddl3w4r3_byp4ss}`, you need to:

1. **Discover the protected route**: The `/monitoring/internal-status` page is an internal diagnostics dashboard protected by middleware
2. **Identify the Next.js version**: Check response headers or `/_next/` assets to confirm the application runs Next.js <= 15.2.2
3. **Research CVE-2025-29927**: Understand how the `x-middleware-subrequest` header bypasses middleware
4. **Craft the exploit request**: Send a request with the header `x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware`
5. **Access the page**: The middleware is skipped, and the internal status page renders with the flag

### Exploit Command

```bash
curl -H "x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware" \
  http://localhost:3000/monitoring/internal-status
```

The header value must contain the middleware module name (`middleware` for root-level middleware, or `src/middleware` if using a `src/` directory) repeated 5 times, separated by colons.

## Remediation

### Immediate Actions

1. **Upgrade Next.js**: Update to version 15.2.3 or later, which patches the vulnerability
2. **Defense in Depth**: Never rely solely on middleware for access control. Implement server-side authentication checks in route handlers and page components
3. **WAF Rules**: Block requests containing the `x-middleware-subrequest` header from external sources

### Code Fixes

**Before (Vulnerable Pattern):**

```typescript
// middleware.ts - sole layer of protection
export function middleware(request: NextRequest) {
  const token = request.cookies.get("authToken")?.value;
  if (!token) return NextResponse.redirect(new URL("/login", request.url));
  return NextResponse.next();
}

// app/admin/page.tsx - trusts middleware entirely
export default function AdminPage() {
  return <AdminDashboard />;
}
```

**After (Defense in Depth):**

```typescript
// app/admin/page.tsx - validates auth independently
import { getAuthenticatedUser } from "@/lib/server-auth";

export default async function AdminPage() {
  const user = await getAuthenticatedUser();
  if (!user || user.role !== "ADMIN") redirect("/login");
  return <AdminDashboard />;
}
```

## OWASP Classification

- **A01:2021 - Broken Access Control**: The middleware bypass allows unauthorized access to protected resources
- **A04:2021 - Insecure Design**: Relying on a single middleware layer without defense in depth

## References

- [CVE-2025-29927](https://nvd.nist.gov/vuln/detail/CVE-2025-29927)
- [Next.js Security Advisory](https://github.com/advisories/GHSA-f82v-jwr5-mffw)
- [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
- [CWE-290: Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html)
