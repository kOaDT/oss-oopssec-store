# CSRF + Self-XSS Profile Takeover Chain

## Overview

This vulnerability chains a missing CSRF defense on the profile update endpoint with a stored Self-XSS in the `bio` field. Each issue alone is limited — Self-XSS is generally treated as low-severity because the victim has to inject their own payload — but combining them lets an attacker plant a stored XSS payload in any logged-in victim's profile from an external page, escalating Self-XSS into a full stored XSS in shared views.

`POST /api/user/profile` accepts both `application/json` and `application/x-www-form-urlencoded` request bodies, performs no anti-CSRF check, and is reachable while the auth cookie (`SameSite: lax`) is attached.

## Why This Is Dangerous

- **Self-XSS becomes weaponized** — a payload normally requiring victim cooperation can be planted by any malicious page they visit.
- **Stored payload in shared views** — once written into the bio, anyone who views the profile (including admins) executes the payload.
- **Form-encoded body bypasses simple CSRF heuristics** — defenses that only inspect JSON content types miss this entirely.
- **Lateral movement** — attacker code runs in the victim's authenticated session, against the same origin as the rest of the app.

## Vulnerable Code

The auth cookie is `SameSite: lax`, permissive enough for top-level navigations and same-origin sub-requests:

```typescript
response.cookies.set("authToken", token, {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "lax",
  maxAge: 60 * 60 * 24 * 7,
  path: "/",
});
```

The profile endpoint accepts either JSON or form-encoded bodies, with no CSRF token, no Origin/Referer enforcement, and no sanitization of `bio`:

```typescript
export const POST = withAuth(async (request, _context, user) => {
  let displayName: string | undefined;
  let bio: string | undefined;
  const contentType = request.headers.get("content-type") || "";

  if (contentType.includes("application/x-www-form-urlencoded")) {
    const formData = await request.text();
    const params = new URLSearchParams(formData);
    displayName = params.get("displayName") ?? undefined;
    bio = params.get("bio") ?? undefined;
  } else {
    const body = await request.json();
    displayName = body.displayName;
    bio = body.bio;
  }

  await prisma.user.update({
    where: { id: user.id },
    data: {
      ...(displayName !== undefined && { displayName }),
      ...(bio !== undefined && { bio }),
    },
  });
});
```

Form-encoded requests are a "simple" cross-origin request in CORS terms — they can be sent from any page using a `<form>` submission without triggering a CORS preflight, which is precisely why CSRF defenses must not depend on content-type alone.

## Secure Implementation

Apply layered defenses — the CSRF and the XSS halves of the chain both need their own fix.

**Anti-CSRF token on every state change.** Issue a per-session token, send it via a custom header, and reject any state-changing request that does not present it:

```typescript
const sessionToken = request.cookies.get("csrfToken")?.value;
const requestToken = request.headers.get("x-csrf-token");

if (!sessionToken || sessionToken !== requestToken) {
  return NextResponse.json({ error: "Invalid CSRF token" }, { status: 403 });
}
```

**Restrict accepted content types.** APIs that only consume JSON should reject everything else; this alone defeats trivial cross-origin form submissions:

```typescript
if (!contentType.includes("application/json")) {
  return NextResponse.json(
    { error: "Content-Type must be application/json" },
    { status: 415 }
  );
}
```

**Tighten cookies.** Move the auth cookie to `sameSite: "strict"`, or split sessions into a `lax` navigation cookie and a `strict` mutation cookie.

**Sanitize stored content.** Treat `bio` as untrusted on write _and_ on read. Strip HTML server-side with `DOMPurify.sanitize(...)` against an allowlist, and render through React's default escaping rather than `innerHTML`.

## References

- [OWASP — Cross-Site Request Forgery](https://owasp.org/www-community/attacks/csrf)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [CWE-352: Cross-Site Request Forgery](https://cwe.mitre.org/data/definitions/352.html)
- [MDN — SameSite cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite)
