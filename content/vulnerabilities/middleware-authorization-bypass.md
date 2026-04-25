# Next.js Middleware Authorization Bypass (CVE-2025-29927)

## Overview

CVE-2025-29927 lets an external request skip Next.js middleware entirely by setting the `x-middleware-subrequest` header. The header is part of an internal mechanism Next.js uses to prevent middleware recursion when one middleware invokes another, but versions before 15.2.3 do not check that the header originated from an internal subrequest. Any client can send it.

In this challenge, an internal diagnostics page (`/monitoring/internal-status`) is protected solely by middleware. Bypassing the middleware exposes the page to anyone, with no authentication.

**CVSS Score:** 9.1 (Critical)

## Affected Versions

- Next.js 11.1.4 through 15.2.2 (patched in 15.2.3, with backports for 14.x, 13.x and 12.x)

## Why This Is Dangerous

- **Single-layer auth collapses** — apps that rely on middleware as the only access-control gate fall open instantly.
- **Trivial exploit** — a single HTTP header, no credentials, no setup.
- **Wide reach** — every middleware-enforced policy is affected: auth, rate limiting, geo-blocking, A/B routing.
- **Pre-auth on every protected route** — internal dashboards, admin panels, draft content, signed-URL endpoints all become reachable.

## Vulnerable Pattern

A typical Next.js auth middleware that is the sole layer of protection looks like this:

```typescript
// middleware.ts
export function middleware(request: NextRequest) {
  const token = request.cookies.get("authToken")?.value;
  if (!token) return NextResponse.redirect(new URL("/login", request.url));
  return NextResponse.next();
}

// app/admin/page.tsx — trusts middleware entirely
export default function AdminPage() {
  return <AdminDashboard />;
}
```

When a request includes `x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware` (or `src/middleware:…` for `src/`-layout projects), affected versions short-circuit the middleware execution and serve the underlying route directly. The page handler then renders without ever consulting the auth cookie.

## Secure Implementation

This bug lives in the framework, so the fix is primarily an upgrade — but the underlying lesson is that middleware alone is not access control.

**Upgrade Next.js** to 15.2.3 or later. For older majors, take the corresponding patched release in the 14.x / 13.x / 12.x lines.

**Authorize inside route handlers and server components.** Middleware is fine for redirects and cosmetic gating, but every protected route must independently verify the user's identity and role:

```typescript
import { redirect } from "next/navigation";
import { getAuthenticatedUser } from "@/lib/server-auth";

export default async function AdminPage() {
  const user = await getAuthenticatedUser();
  if (!user || user.role !== "ADMIN") redirect("/login");
  return <AdminDashboard />;
}
```

**Strip the bypass header at the edge.** Configure a WAF, reverse proxy, or CDN rule to drop incoming `x-middleware-subrequest` headers from external clients. This is a belt-and-braces measure for any request that reaches the application from outside the trust boundary.

## References

- [CVE-2025-29927](https://nvd.nist.gov/vuln/detail/CVE-2025-29927)
- [Next.js Security Advisory — GHSA-f82v-jwr5-mffw](https://github.com/advisories/GHSA-f82v-jwr5-mffw)
- [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
- [CWE-290: Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html)
