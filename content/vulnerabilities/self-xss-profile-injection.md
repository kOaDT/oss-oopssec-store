# Self-XSS - Profile Bio Injection

## Overview

This vulnerability demonstrates a stored Cross-Site Scripting (XSS) flaw in the profile bio editor. The application allows users to enter rich-text content in their bio field, which is stored without sanitization on the server and rendered on the frontend using React's `dangerouslySetInnerHTML`. This enables an attacker to inject malicious HTML containing event-handler-based JavaScript that executes whenever the profile is viewed.

## Why This Is Dangerous

### Stored Self-XSS via Profile Bio

When a profile bio field accepts and renders arbitrary HTML without sanitization, it creates a persistent attack surface:

1. **Persistent execution** - The malicious payload is stored in the database and triggers every time the profile page is loaded
2. **Credential theft** - Attackers can exfiltrate session tokens, cookies, or other sensitive data rendered on the page
3. **Social engineering amplifier** - A convincing profile page with injected scripts can trick other users into interacting with malicious content
4. **Chained attacks** - Self-XSS in a profile can be combined with CSRF or other vectors to escalate from self-only to victim-targeting attacks

## The Vulnerability

The vulnerability exists in two layers of the application:

1. **API endpoint** (`POST /api/user/profile`) - Accepts and stores the bio field without any HTML sanitization
2. **Frontend component** (`ProfileClient`) - Renders the stored bio using `dangerouslySetInnerHTML`, bypassing React's built-in escaping

### Vulnerable Code

**API Endpoint (No Sanitization):**

```typescript
const updatedUser = await prisma.user.update({
  where: { id: user.id },
  data: {
    ...(displayName !== undefined && { displayName }),
    ...(bio !== undefined && { bio }), // ❌ No sanitization - raw HTML stored directly
  },
});
```

**Frontend Rendering (Unsafe HTML Injection):**

```typescript
{profile.bio && (
  <div
    className="mt-2 rounded-lg border ..."
    dangerouslySetInnerHTML={{ __html: profile.bio }} // ❌ Raw HTML rendered without sanitization
  />
)}
```

**Important:** React's `dangerouslySetInnerHTML` does **not** execute `<script>` tags inserted into the DOM. This is a behavior of the browser's `innerHTML` API, not a security feature. However, event-handler attributes on other HTML elements (such as `onerror`, `onload`, `onmouseover`) **will** execute JavaScript normally. This means payloads must use event handlers rather than `<script>` blocks.

## Exploitation

### How to Retrieve the Flag

To retrieve the flag, you need to save an HTML payload in the bio field. The profile update API detects HTML tags in the bio content and includes the flag in the response.

**Exploitation Steps:**

1. Log in and navigate to your profile page (`/profile`)
2. In the bio editor field, enter any HTML payload
3. Save the profile
4. The API response will contain the flag
5. Additionally, the payload is rendered via `dangerouslySetInnerHTML`, proving the XSS executes in the browser

**Simple Payload:**

```html
<img src="x" onerror="alert('XSS')" />
```

**Payload with DOM Manipulation:**

```html
<img
  src="x"
  onerror="const d=document.createElement('div');d.style.cssText='position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);background:#000;color:#0f0;padding:20px;font-family:monospace;z-index:9999;border:2px solid #0f0';d.textContent='XSS Executed';document.body.appendChild(d)"
/>
```

**Using SVG onload:**

```html
<svg onload="alert('XSS')"></svg>
```

**Why `<script>` Tags Do Not Work:**

```html
<!-- ❌ This will NOT execute -->
<script>
  alert("XSS");
</script>

<!-- ✅ This WILL execute -->
<img src="x" onerror="alert('XSS')" />
```

When HTML is inserted via `innerHTML` (which is what `dangerouslySetInnerHTML` uses under the hood), the browser parses the markup but does not execute any `<script>` elements. This is defined in the HTML5 specification. Event handler attributes, however, are attached to DOM elements as they are created and will fire when the corresponding event occurs.

### Secure Implementation

```typescript
// ✅ SECURE - Sanitize on the server before storing
import DOMPurify from "isomorphic-dompurify";

const updatedUser = await prisma.user.update({
  where: { id: user.id },
  data: {
    displayName,
    bio: DOMPurify.sanitize(bio.trim()),
  },
});
```

```typescript
// ✅ SECURE - Use React's default escaping (renders as plain text)
<div className="prose dark:prose-invert max-w-none">
  {bio} {/* React automatically escapes HTML entities */}
</div>
```

```typescript
// ✅ SECURE - If rich HTML is needed, sanitize before rendering
import DOMPurify from "isomorphic-dompurify";

<div
  dangerouslySetInnerHTML={{
    __html: DOMPurify.sanitize(bio, {
      ALLOWED_TAGS: ["b", "i", "em", "strong", "a", "p", "br", "ul", "ol", "li"],
      ALLOWED_ATTR: ["href", "target", "rel"],
    }),
  }}
/>
```

## References

- [OWASP Top 10 - Cross-Site Scripting (XSS)](<https://owasp.org/www-project-top-ten/2017/A7_2017-Cross-Site_Scripting_(XSS)>)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
- [React Security - dangerouslySetInnerHTML](https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html)
- [HTML5 Specification - innerHTML Script Execution](https://html.spec.whatwg.org/multipage/dynamic-markup-insertion.html#dom-element-innerhtml)
- [DOMPurify - Client-Side HTML Sanitization](https://github.com/cure53/DOMPurify)
