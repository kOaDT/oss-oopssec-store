# Cross-Site Request Forgery (CSRF)

## Overview

CSRF abuses the fact that browsers automatically attach cookies to outbound requests. If a state-changing endpoint relies only on the auth cookie to identify the caller, any page the victim visits can issue a request to that endpoint while logged in, and the server cannot tell the forged request from a legitimate one.

In this challenge, the order status endpoint (`PATCH/POST /api/orders/[id]`) accepts admin-only state changes with no anti-CSRF token, no origin check, and a `sameSite: "lax"` auth cookie that is permissive enough for the attack to land.

## Why This Is Dangerous

- **Privileged state changes** — an admin who visits a malicious page silently mutates business data (order status, configuration, etc.).
- **No credential theft required** — the browser supplies the cookie automatically; the attacker never sees the token.
- **Victim never notices** — the request fires in the background and returns to the attacker, not the victim.
- **Chains with other bugs** — combined with XSS, open redirects, or weak email filtering, CSRF reaches deep into the application.

## Vulnerable Code

The auth cookie is configured with `sameSite: "lax"`:

```typescript
response.cookies.set("authToken", token, {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "lax",
  maxAge: 60 * 60 * 24 * 7,
  path: "/",
});
```

`lax` blocks cookies on cross-site `fetch`/`XHR`, but allows them on top-level navigations and on same-origin requests, which is all the exploit needs once the attacker can host content under the same origin (or convince the browser to navigate).

The order status handler accepts the request body with no anti-forgery verification:

```typescript
const updateOrderStatus = async (request, orderId, user) => {
  if (user.role !== "ADMIN") {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  // No CSRF token check, no Origin/Referer enforcement.
  // The browser attached the auth cookie automatically.
  const { status } = await request.json();

  await prisma.order.update({ where: { id: orderId }, data: { status } });
  return NextResponse.json({ success: true });
};
```

| `sameSite` | Behavior on cross-site requests                   | CSRF protection |
| ---------- | ------------------------------------------------- | --------------- |
| `strict`   | Cookie never sent cross-site                      | Strong          |
| `lax`      | Sent on top-level GET; not on cross-site POST/XHR | Partial         |
| `none`     | Always sent (requires `secure: true`)             | None            |

## Secure Implementation

Use defense in depth — no single control is enough on its own.

**Synchronizer / double-submit token.** Issue an unguessable token bound to the session and require it on every state-changing request:

```typescript
const cookieToken = request.cookies.get("csrfToken")?.value;
const headerToken = request.headers.get("X-CSRF-Token");

if (!cookieToken || cookieToken !== headerToken) {
  return NextResponse.json({ error: "Invalid CSRF token" }, { status: 403 });
}
```

**Tighten the cookie.** Use `sameSite: "strict"` for cookies that authenticate sensitive operations, or split sessions into a `lax` cookie for navigation and a `strict` cookie for mutations.

**Verify Origin / Referer.** Reject state-changing requests whose `Origin` does not match an allowlist of trusted origins:

```typescript
const origin = request.headers.get("origin");
if (!ALLOWED_ORIGINS.includes(origin ?? "")) {
  return NextResponse.json({ error: "Invalid origin" }, { status: 403 });
}
```

**Use safe HTTP methods correctly.** `GET` must never change state; that alone closes a class of trivial exploits.

## References

- [OWASP — Cross-Site Request Forgery](https://owasp.org/www-community/attacks/csrf)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [CWE-352: Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html)
- [MDN — SameSite cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite)
