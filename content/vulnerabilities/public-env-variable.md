# Public Environment Variable Exposure

## Overview

In Next.js, any environment variable whose name starts with `NEXT_PUBLIC_` is inlined into the client JavaScript bundle at build time. The value is no longer "in the environment" by the time a browser fetches the page — it is plain text inside a static asset that anyone can download. Treating these variables as a place to keep secrets is a category error.

In this challenge, the checkout client reads `NEXT_PUBLIC_PAYMENT_SECRET` and sends it as the `X-Payment-Auth` header on every order request. The "secret" travels both inside the bundle and on every outbound checkout request.

## Why This Is Dangerous

- **Compile-time inlining is non-reversible** — the value is part of the deployed bundle; rotating it requires a rebuild and redeploy.
- **Visible in two places** — both the static chunks served from `/_next/static/chunks/` and the network tab of any user's browser.
- **Minification removes the variable name** — the string survives even when the binding does, so grep-by-name searches miss it; attackers grep for the value shape.
- **Misleading naming** — `process.env.*` _looks_ like a runtime environment lookup; in client code it is a build-time string substitution.

## Vulnerable Code

```typescript
const paymentSecret = process.env.NEXT_PUBLIC_PAYMENT_SECRET ?? "";

await fetch("/api/orders", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "X-Payment-Auth": paymentSecret,
  },
  body: JSON.stringify(payload),
});
```

At build time, SWC replaces `process.env.NEXT_PUBLIC_PAYMENT_SECRET` with the literal string. The compiled chunk that ships to browsers contains the value directly, with the surrounding identifier minified to a one-letter local. The browser then attaches the value to every checkout request, where any user can copy it from DevTools.

## Secure Implementation

Anything secret stays server-side; only non-sensitive configuration crosses to the client.

**Use a server-only environment variable.** Drop the `NEXT_PUBLIC_` prefix so the value is never exposed to the browser, and use it inside a server-only path (a Route Handler, a Server Component, a server action). For the checkout flow specifically, the payment authentication header should be added inside the route handler that proxies the call to the payment processor — not in the React component that runs in the browser:

```typescript
// app/api/orders/route.ts (server-only)
const paymentSecret = process.env.PAYMENT_SECRET;
// add the header here, where the value never leaves the server
```

**Treat any `NEXT_PUBLIC_*` value as published.** Use it for things that are inherently public: feature flags, public API URLs, analytics IDs. Anything secret — payment tokens, signing keys, third-party API credentials — never gets that prefix.

**Audit and rotate after the fact.** If a secret has appeared in a `NEXT_PUBLIC_*` variable, assume it is leaked: rotate it at the source (payment provider, auth provider) and rebuild. Removing the variable from the next deployment does not revoke the value already in clients' caches.

## References

- [Next.js — Environment Variables (`NEXT_PUBLIC_`)](https://nextjs.org/docs/app/building-your-application/configuring/environment-variables#bundling-environment-variables-for-the-browser)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-540: Inclusion of Sensitive Information in Source Code](https://cwe.mitre.org/data/definitions/540.html)
- [OWASP Top 10 — A05:2021 Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
