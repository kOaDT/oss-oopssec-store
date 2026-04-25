# Stored Cross-Site Scripting (XSS)

## Overview

Stored XSS happens when user-supplied content is persisted by the server and later rendered as HTML in another user's browser. The injected markup runs with the privileges of the rendering origin, so anything the page can do — read cookies, call APIs, deface the UI — the attacker can do too.

In this challenge, the product review feature accepts a `content` string from the API, stores it as-is, and the product page renders it via `element.innerHTML = review.content`, bypassing React's automatic escaping.

## Why This Is Dangerous

- **Persistent compromise** — every visitor to the affected product page runs the attacker's code.
- **Session hijacking and account takeover** — any data the rendering page can read (storage, in-memory state, CSRFable endpoints) is reachable.
- **Phishing inside the trusted origin** — injected markup can rewrite the page to harvest credentials.
- **Privilege escalation** — admins viewing the page execute the payload with their privileges.

## Vulnerable Code

The API stores the review body verbatim:

```typescript
const review = await prisma.review.create({
  data: {
    productId: id,
    content: content.trim(),
    author,
  },
});
```

The product page injects the stored content as raw HTML:

```tsx
useEffect(() => {
  reviews.forEach((review) => {
    const reviewElement = reviewRefs.current[review.id];
    if (reviewElement && reviewElement.innerHTML !== review.content) {
      reviewElement.innerHTML = review.content;
    }
  });
}, [reviews]);
```

`element.innerHTML = ...` parses the assigned string as HTML and executes any `<script>` or event-handler attributes inside it. React would normally escape `{review.content}`; using `innerHTML` opts back into the unsafe path.

## Secure Implementation

Render text as text. React's default JSX interpolation escapes HTML entities, so the simplest fix is to delete the imperative `innerHTML` assignment and let JSX handle it:

```tsx
<div className="text-slate-700 dark:text-slate-300">{review.content}</div>
```

If reviewers really need rich text, sanitize on the server before storing _and_ on the client before rendering, and only allow a small allowlist of tags and attributes:

```typescript
import DOMPurify from "isomorphic-dompurify";

const safe = DOMPurify.sanitize(content.trim(), {
  ALLOWED_TAGS: ["b", "i", "em", "strong", "p", "br"],
  ALLOWED_ATTR: [],
});
```

Layer a strict Content Security Policy (`default-src 'self'; script-src 'self'`) so that even if escaping fails, inline scripts and remote scripts are blocked. Output encoding is the primary defense; CSP is the safety net.

## References

- [OWASP — Cross-Site Scripting (XSS)](https://owasp.org/www-community/attacks/xss/)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
- [MDN — Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
