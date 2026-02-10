# Cross-Site Request Forgery (CSRF)

## Overview

This vulnerability demonstrates a critical security flaw where the application performs state-changing operations (like updating order statuses) without proper CSRF protection. This allows attackers to trick authenticated users into executing unwanted actions on the application by making requests from a malicious website.

The application uses HTTP-only cookies with `sameSite: "lax"` for authentication. While this protects against some cross-site scenarios, the `lax` policy still allows cookies to be sent on same-origin requests and on top-level navigations from external sites. Combined with the lack of CSRF tokens or origin validation, this makes the application vulnerable to CSRF attacks.

## Why This Is Dangerous

### CSRF Attack Vector

When an application accepts state-changing requests without CSRF protection, it creates a serious security vulnerability:

1. **Unauthorized actions** - Attackers can force users to perform actions they didn't intend
2. **Cookie-based authentication** - Browsers automatically include cookies with requests, so the attacker doesn't need access to the token
3. **User unawareness** - Victims may not realize an attack occurred until it's too late
4. **Privilege abuse** - Attackers can exploit elevated privileges of authenticated users
5. **Business impact** - Can lead to data modification, unauthorized transactions, or system compromise

### What This Means

**Never trust that a request comes from your own application.** The server must always:

- Verify the origin of state-changing requests
- Use CSRF tokens to validate request authenticity
- Implement SameSite cookie attributes (`strict` for sensitive operations)
- Validate Referer/Origin headers for sensitive operations

## The Vulnerability

In this application, the order status update endpoint (`PATCH /api/orders/[id]`) is vulnerable to CSRF attacks because:

1. **No CSRF token validation** - The endpoint accepts requests without verifying CSRF tokens
2. **No origin verification** - The server doesn't check the request origin or referer
3. **State-changing operation** - The endpoint modifies critical business data (order status)
4. **Weak cookie policy** - The authentication cookie uses `sameSite: "lax"` instead of `"strict"`

### Vulnerable Code

**Cookie Configuration:**

The application sets the authentication cookie with `sameSite: "lax"`:

```typescript
response.cookies.set("authToken", token, {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "lax", // ❌ Should be "strict" for sensitive operations
  maxAge: 60 * 60 * 24 * 7,
  path: "/",
});
```

While `httpOnly: true` prevents JavaScript from reading the cookie (protecting against XSS-based token theft), the `sameSite: "lax"` policy allows the cookie to be sent on same-origin requests, making CSRF attacks possible from the same domain.

**Order Update Endpoint (No CSRF Protection):**

```typescript
export async function PATCH(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const user = await getAuthenticatedUser(request);
  // ❌ No CSRF token validation
  // ❌ No origin/referer verification
  // The cookie is automatically included by the browser
  const { status } = await request.json();
  await prisma.order.update({ where: { id }, data: { status } });
}
```

### Understanding `sameSite` Values

| Value    | Behavior                                                                    | CSRF Protection |
| -------- | --------------------------------------------------------------------------- | --------------- |
| `strict` | Cookie never sent on cross-site requests                                    | Strong          |
| `lax`    | Cookie sent on top-level navigations (GET) but not on cross-site POST/fetch | Moderate        |
| `none`   | Cookie always sent (requires `secure: true`)                                | None            |

In this lab, the exploit page is served from the same origin, so `lax` does not block the request. In a real-world scenario, `lax` would block cross-origin `fetch` with `credentials: "include"`, but would still allow form-based GET requests that could be exploited depending on the endpoint design.

## Exploitation

### How to Retrieve the Flag

To retrieve the flag `OSS{cr0ss_s1t3_r3qu3st_f0rg3ry}`, you need to exploit the CSRF vulnerability:

**Prerequisites:**

1. You must find the way to be logged in as an administrator
2. There must be at least one order in the system (check `/admin` to see orders)

**Exploitation Steps:**

1. **Log in as admin:**

2. **Find the exploit file:**
   - Inspect the HTML source of the admin dashboard page
   - Look for hidden links or comments in the page source
   - You should find a link to `/exploits/csrf-attack.html`

3. **Open the malicious website (simulated attacker's site):**
   - Navigate to the exploit file URL or open it directly
   - You can access it via: `http://localhost:3000/exploits/csrf-attack.html`
   - The page is designed to look like a phishing email from PayPal

4. **Trigger the CSRF attack:**
   - Click the "Secure My Account Now" button in the phishing email
   - The page sends a `POST` request to `/api/orders/ORD-003` with `credentials: "include"`
   - The browser automatically attaches your `authToken` cookie to the request
   - No JavaScript access to the token is needed — the browser handles cookie inclusion automatically

5. **Retrieve the flag:**
   - After the attack, check the admin dashboard again
   - The order status should have changed
   - The flag `OSS{cr0ss_s1t3_r3qu3st_f0rg3ry}` will be returned in the API response

**Alternative: Manual Exploitation**

You can also trigger the CSRF attack manually from the browser console while logged in:

```javascript
fetch("/api/orders/ORD-003", {
  method: "POST",
  credentials: "include",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ status: "DELIVERED" }),
})
  .then((r) => r.json())
  .then(console.log);
```

The key insight is that `credentials: "include"` tells the browser to send cookies along with the request. Since the `authToken` cookie has `sameSite: "lax"`, it is included in same-origin requests automatically.

## Secure Implementation

### 1. CSRF Tokens

```typescript
import { randomBytes } from "crypto";

const generateCSRFToken = () => {
  return randomBytes(32).toString("hex");
};

// Store token in session or return it to client
const csrfToken = generateCSRFToken();
response.cookies.set("csrfToken", csrfToken, {
  httpOnly: true,
  secure: true,
  sameSite: "strict",
});

// Validate token on state-changing requests
const tokenFromCookie = request.cookies.get("csrfToken")?.value;
const tokenFromHeader = request.headers.get("X-CSRF-Token");
if (tokenFromCookie !== tokenFromHeader) {
  return NextResponse.json({ error: "Invalid CSRF token" }, { status: 403 });
}
```

### 2. SameSite Cookie Attribute

```typescript
response.cookies.set("authToken", token, {
  httpOnly: true,
  secure: true,
  sameSite: "strict", // ✅ Prevents cross-site cookie sending
  maxAge: 60 * 60 * 24 * 7,
  path: "/",
});
```

### 3. Origin/Referer Verification

```typescript
const origin = request.headers.get("origin");
const referer = request.headers.get("referer");
const allowedOrigins = ["https://yourdomain.com"];

if (!allowedOrigins.includes(origin || "")) {
  return NextResponse.json({ error: "Invalid origin" }, { status: 403 });
}
```

### 4. Double Submit Cookie Pattern

```typescript
// Client sends token in both cookie and custom header
// Server verifies they match
const cookieToken = request.cookies.get("csrfToken")?.value;
const headerToken = request.headers.get("X-CSRF-Token");

if (cookieToken !== headerToken) {
  return NextResponse.json(
    { error: "CSRF validation failed" },
    { status: 403 }
  );
}
```

## References

- [OWASP Top 10 - Cross-Site Request Forgery (CSRF)](https://owasp.org/www-community/attacks/csrf)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [CWE-352: Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html)
- [MDN - SameSite Cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite)
- [MDN - CSRF Protection](https://developer.mozilla.org/en-US/docs/Glossary/CSRF)
