# Cross-Site Request Forgery (CSRF)

## Overview

This vulnerability demonstrates a critical security flaw where the application performs state-changing operations (like updating order statuses) without proper CSRF protection. This allows attackers to trick authenticated users into executing unwanted actions on the application by making requests from a malicious website.

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
2. **Cookie-based authentication** - The application sets an authentication cookie that browsers automatically include in requests
3. **State-changing operation** - The endpoint modifies critical business data (order status)
4. **No origin verification** - The server doesn't check the request origin or referer

### Vulnerable Code

**Authentication Cookie (No SameSite Protection):**

```typescript
response.cookies.set("authToken", token, {
  httpOnly: false,
  secure: false,
  sameSite: "lax", // ❌ Should be "strict" for sensitive operations
  maxAge: 60 * 60 * 24 * 7,
  path: "/",
});
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
   - **Note:** In a real-world attack, this would be hosted on a completely different domain (e.g., `https://evil-attacker.com/special-offer.html`). For this demonstration, we simulate the attacker's website on the same domain, but the CSRF attack still works because the browser automatically includes authentication cookies regardless of where the form is hosted.

4. **Trigger the CSRF attack:**
   - Click the "Claim My Reward" button to submit a form
   - The form submits a `POST` request to change order `ORD-001` status to `DELIVERED`
   - Your browser automatically includes your authentication cookie with the request
   - **This simulates a real attack scenario:** In production, an attacker would host a similar malicious page on their own domain (e.g., `https://evil-site.com/special-offer.html`). When a logged-in admin visits that page, the attacker's website has access to the authentication token stored in the cookie and uses it to execute an unauthorized operation. The browser automatically sends the cookie with the form submission, allowing the attacker to perform actions on behalf of the authenticated user without their explicit consent.

5. **Retrieve the flag:**
   - After the attack, check the admin dashboard again
   - The order status should have changed
   - The flag `OSS{cr0ss_s1t3_r3qu3st_f0rg3ry}` will be returned in the API response

**Alternative: Manual Exploitation**

You can also create your own HTML file with this content and host it on a different domain to simulate a real-world attack:

```html
<!DOCTYPE html>
<html>
  <body>
    <form
      id="csrfForm"
      action="http://localhost:3000/api/orders/ORD-001"
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

**Note:** The browser automatically includes cookies from the target domain when submitting forms, even cross-origin. The `sameSite: "lax"` setting allows cookies to be sent with top-level navigations, making this attack possible.

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
