# Self-XSS — Profile Bio Injection

## Overview

The profile editor stores the user's `bio` as raw HTML and the profile page renders it via `dangerouslySetInnerHTML`, bypassing React's automatic escaping. On its own, this is "Self-XSS": only the account owner can put markup into their own bio, and only their browser executes it.

The Self-XSS becomes a real attack when chained with the missing CSRF defense on the same `POST /api/user/profile` endpoint (see the related [CSRF + Self-XSS Profile Takeover](/vulnerabilities/csrf-profile-takeover-chain) write-up). At that point, an attacker can plant the payload into any logged-in victim's bio from a malicious page, and the payload then runs for anyone — including admins — who views that profile.

## Why This Is Dangerous

- **Persistent** — the payload lives in the database and runs every time the bio is rendered.
- **Chains with CSRF** — Self-XSS that "only hurts you" becomes stored XSS for everyone the moment another endpoint can write the bio for you.
- **`dangerouslySetInnerHTML` is the unsafe path** — React does not escape its argument; the HTML is parsed and DOM event handlers fire normally.
- **Misleading "no `<script>` execution" rule** — `innerHTML` does not run inserted `<script>` tags, but `<img onerror>`, `<svg onload>`, and similar event handlers do, so the protection is illusory.

## Vulnerable Code

The bio is written through to the database without sanitization:

```typescript
const updatedUser = await prisma.user.update({
  where: { id: user.id },
  data: {
    ...(displayName !== undefined && { displayName }),
    ...(bio !== undefined && { bio }),
  },
});
```

The profile page renders it as HTML:

```tsx
{
  profile.bio && (
    <div
      className="mt-2 rounded-lg border ..."
      dangerouslySetInnerHTML={{ __html: profile.bio }}
    />
  );
}
```

`dangerouslySetInnerHTML` calls `element.innerHTML = profile.bio` under the hood. The browser parses the markup and attaches DOM event handlers (`onerror`, `onload`, `onmouseover`) to elements as they are created; those handlers run normally even though `<script>` tags inserted via `innerHTML` do not.

## Secure Implementation

Render text as text — for nearly every "rich" bio use case, the right answer is plain text plus a simple Markdown subset:

```tsx
<p className="prose dark:prose-invert max-w-none whitespace-pre-line">
  {profile.bio}
</p>
```

JSX interpolation escapes HTML entities by default, so injected markup renders as visible characters instead of executing.

If structured HTML is genuinely required, sanitize with a strict allowlist on both the write and the read paths:

```typescript
import DOMPurify from "isomorphic-dompurify";

const safeBio = DOMPurify.sanitize(bio, {
  ALLOWED_TAGS: ["b", "i", "em", "strong", "a", "p", "br", "ul", "ol", "li"],
  ALLOWED_ATTR: ["href", "target", "rel"],
});
```

Combine with the broader fixes:

- Add CSRF protection on every state-changing endpoint so a remote page cannot write someone else's bio.
- Apply a strict Content Security Policy (`default-src 'self'; script-src 'self'`) to neutralize a single missed escaping site.
- Never use `dangerouslySetInnerHTML` with user input unless the input has already passed through a vetted sanitizer.

## References

- [OWASP — Cross-Site Scripting (XSS)](https://owasp.org/www-community/attacks/xss/)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
- [React — `dangerouslySetInnerHTML`](https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html)
- [HTML Spec — `innerHTML` does not execute `<script>`](https://html.spec.whatwg.org/multipage/dynamic-markup-insertion.html#dom-element-innerhtml)
