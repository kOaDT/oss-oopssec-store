# Open Redirect

## Overview

Open redirect happens when an application takes a destination URL from user input and navigates to it without checking that it stays inside the trust boundary. The redirect originates from the legitimate domain, which is exactly what makes it useful to attackers: phishing links carry the real product's hostname, and email gateways do not flag them.

In this challenge, the login page reads a `redirect` query parameter and, after successful authentication, navigates the browser to whatever value it contains.

## Why This Is Dangerous

- **Credential phishing** — a link to `/login?redirect=https://evil.example/login` starts on the real domain and lands on a look-alike harvester after the user logs in.
- **Internal endpoint reachability** — unlinked admin or debug pages become reachable post-login by anyone who knows their path.
- **Token leakage via referrer** — the destination receives a `Referer` header pointing back at the authenticated session URL.
- **Filter evasion** — users, mail clients, and reputation systems trust the originating domain.

## Vulnerable Code

```tsx
const redirect = searchParams.get("redirect");

// after a successful POST /api/auth/login
if (redirect) {
  window.location.href = redirect;
}
```

`redirect` is taken straight from the query string and used as a navigation target. Any value the attacker can put in the URL — `https://evil.example`, `//evil.example`, `javascript:...`, or a path to an internal page — is honored.

## Secure Implementation

Treat the redirect parameter as untrusted and only honor values that resolve inside the application:

```tsx
function safeRedirect(target: string | null): string {
  if (!target) return "/";
  // Only allow same-origin paths.
  if (!target.startsWith("/") || target.startsWith("//")) return "/";
  return target;
}

window.location.href = safeRedirect(redirect);
```

For server-side redirects, parse the candidate URL and compare it against an allowlist of origins instead of trying to filter strings:

```typescript
const url = new URL(target, request.url);
if (url.origin !== new URL(request.url).origin) {
  return NextResponse.redirect(new URL("/", request.url));
}
```

Do not rely on denylists of bad characters or schemes — encoding tricks (`//evil`, `\\evil`, `%2f%2fevil`) consistently defeat them. The control plane is "is this URL inside my origin?", not "does this URL look suspicious?".

## References

- [OWASP — Unvalidated Redirects and Forwards Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
- [CWE-601: URL Redirection to Untrusted Site (Open Redirect)](https://cwe.mitre.org/data/definitions/601.html)
- [PortSwigger — Open redirect](https://portswigger.net/kb/issues/00500100_open-redirection-reflected)
