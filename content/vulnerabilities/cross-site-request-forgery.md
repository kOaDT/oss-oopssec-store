# Cross-Site Request Forgery (CSRF)

## Overview

This vulnerability demonstrates a critical security flaw where the application performs state-changing operations (like updating order statuses) without proper CSRF protection. This allows attackers to trick authenticated users into executing unwanted actions on the application by making requests from a malicious website.

> **Note on Lab Implementation vs Real-World Scenarios:**
>
> For simplicity, this lab uses `localStorage` for authentication since both the vulnerable application and the exploit page are hosted on the same domain (localhost). This allows the attack to work in the lab environment.
>
> However, in a real-world CSRF attack scenario, the exploit would be hosted on a **different domain** (e.g., `malicious-site.com`), making `localStorage` inaccessible due to the Same-Origin Policy. In such cases, CSRF attacks rely on **cookies** being automatically sent with cross-origin requests. The vulnerability would specifically require:
>
> - Session authentication via cookies
> - Cookies without the `SameSite=Strict` attribute (or with `SameSite=None` or `SameSite=Lax` allowing certain cross-site requests)
>
> **Future Enhancement:** Upgrading this lab to use cookie-based authentication with a separate exploit domain would make the attack demonstration more realistic. Contributions via pull requests are welcome!

## Why This Is Dangerous

### CSRF Attack Vector

When an application accepts state-changing requests without CSRF protection, it creates a serious security vulnerability:

1. **Unauthorized actions** - Attackers can force users to perform actions they didn't intend
2. **Cookie-based authentication** - If authentication relies on cookies, browsers automatically include them in cross-origin requests
3. **User unawareness** - Victims may not realize an attack occurred until it's too late
4. **Privilege abuse** - Attackers can exploit elevated privileges of authenticated users
5. **Business impact** - Can lead to data modification, unauthorized transactions, or system compromise

### What This Means

**Never trust that a request comes from your own application.** The server must always:

- Verify the origin of state-changing requests
- Use CSRF tokens to validate request authenticity
- Implement SameSite cookie attributes
- Validate Referer/Origin headers for sensitive operations

## The Vulnerability

In this application, the order status update endpoint (`PATCH /api/orders/[id]`) is vulnerable to CSRF attacks because:

1. **No CSRF token validation** - The endpoint accepts requests without verifying CSRF tokens
2. **No origin verification** - The server doesn't check the request origin or referer
3. **State-changing operation** - The endpoint modifies critical business data (order status)
4. **Authentication mechanism** - The application uses localStorage to store authentication tokens, which allows same-origin attacks

### Important Note About This Demonstration

**This demonstration uses localStorage for authentication**, which means:

- The attack works because the malicious page is hosted on the same domain as the application
- The same-origin policy allows the malicious page to access localStorage from the same domain
- This is a simplified scenario for educational purposes

**In a real-world CSRF attack scenario:**

- Applications typically use **cookies** for authentication instead of localStorage
- With cookie-based authentication, the attack would work from **any external domain**
- Browsers automatically include cookies with cross-origin requests (when `sameSite` is not set to `"strict"`)
- The attacker wouldn't need JavaScript access to localStorage - a simple HTML form submission would be sufficient
- This is why CSRF protection is critical: cookies are automatically sent by browsers, making cross-site attacks possible

### Vulnerable Code

**Current Implementation (localStorage-based):**

This application stores the authentication token in `localStorage` on the client side:

```typescript
// Client-side: Token stored in localStorage
localStorage.setItem("authToken", token);
```

The server reads the token from the `Authorization` header:

```typescript
export async function getAuthenticatedUser(request: NextRequest) {
  const authHeader = request.headers.get("authorization");
  const token = authHeader?.replace("Bearer ", "") || null;
  // ... validates token
}
```

**Order Update Endpoint (No CSRF Protection):**

```typescript
export async function PATCH(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const user = await getAuthenticatedUser(request);
  // ❌ No CSRF token validation
  // ❌ No origin/referer verification
  const { status } = await request.json();
  await prisma.order.update({ where: { id }, data: { status } });
}
```

**What Would Make This a True Cross-Site CSRF:**

If the application used cookies instead of localStorage:

```typescript
// ❌ Vulnerable cookie configuration
response.cookies.set("authToken", token, {
  httpOnly: false,
  secure: false,
  sameSite: "lax", // ❌ Should be "strict" for sensitive operations
  maxAge: 60 * 60 * 24 * 7,
  path: "/",
});
```

With cookie-based authentication, the browser would automatically include the cookie with cross-origin requests, making true cross-site CSRF attacks possible.

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
   - **Note:** In this demonstration, the malicious page is hosted on the same domain as the application. This allows it to access your authentication token from localStorage. In a real-world attack with cookie-based authentication, the malicious page could be hosted on any external domain (e.g., `https://evil-attacker.com/phishing.html`), and the browser would still automatically include authentication cookies with the request.

4. **Trigger the CSRF attack:**
   - Click the "Verify Order Status" button in the phishing email
   - The page reads your authentication token from localStorage and sends a `POST` request to change order `ORD-003` status to `DELIVERED`
   - The request includes your authentication token in the `Authorization` header
   - **This demonstrates the CSRF principle:** The attack works because the malicious page can access localStorage (same-origin) and make authenticated requests on your behalf. In a real-world scenario with cookies, the browser would automatically include authentication cookies with cross-origin requests, making the attack possible from any domain.

5. **Retrieve the flag:**
   - After the attack, check the admin dashboard again
   - The order status should have changed
   - The flag `OSS{cr0ss_s1t3_r3qu3st_f0rg3ry}` will be returned in the API response

**Alternative: Manual Exploitation**

You can also create your own HTML file with this content. Note that with the current localStorage-based authentication, this would only work if hosted on the same domain:

```html
<!DOCTYPE html>
<html>
  <body>
    <form
      id="csrfForm"
      action="http://localhost:3000/api/orders/ORD-003"
      method="POST"
    >
      <input type="hidden" name="status" value="DELIVERED" />
    </form>
    <script>
      const token = localStorage.getItem("authToken");
      fetch("http://localhost:3000/api/orders/ORD-003", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ status: "DELIVERED" }),
      });
    </script>
  </body>
</html>
```

**Note on Real-World CSRF with Cookies:**

If the application used cookie-based authentication instead of localStorage, a true cross-site attack would be possible with a simple form submission (no JavaScript needed):

```html
<!DOCTYPE html>
<html>
  <body>
    <form
      id="csrfForm"
      action="https://target-app.com/api/orders/ORD-003"
      method="POST"
    >
      <input type="hidden" name="status" value="DELIVERED" />
    </form>
    <script>
      document.getElementById("csrfForm").submit();
    </script>
  </body>
</html>
```

In this scenario, the browser would automatically include authentication cookies from `target-app.com` with the form submission, even though the form is hosted on a different domain. This is why `sameSite: "strict"` is crucial for cookie-based authentication.

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

## Flag

The flag for this vulnerability is: **OSS{cr0ss_s1t3_r3qu3st_f0rg3ry}**

The flag can be retrieved by exploiting the CSRF vulnerability to change an order status. When an authenticated admin's order status is successfully modified via a CSRF attack, the flag is returned in the API response.
