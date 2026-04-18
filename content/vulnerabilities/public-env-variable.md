# Public Environment Variable Exposure

## Overview

This vulnerability demonstrates the critical security risk of exposing sensitive environment variables to client-side code. In Next.js applications, any environment variable prefixed with `NEXT_PUBLIC_` is embedded directly into the JavaScript bundle that runs in the user's browser, making it accessible to anyone.

## Why This Is Dangerous

### Client-Side Code Is Always Public

When you use `NEXT_PUBLIC_*` environment variables in Next.js, these values are:

1. **Embedded at build time** into the JavaScript bundle files
2. **Downloaded by every user** who visits your website
3. **Accessible in the browser** through the developer console
4. **Visible in the source code** by viewing page source or inspecting network requests

### What This Means

**Anything stored in a `NEXT_PUBLIC_*` variable is not secret.** It's as public as the HTML, CSS, and JavaScript files served to users. Anyone can:

- Open the browser's developer console (F12)
- Search the downloaded JavaScript chunks in the Sources tab
- Inspect outgoing requests in the Network tab to see the value leaking in headers or request bodies
- View the raw bundle files served from `/_next/static/chunks/`

Note: `process.env` is not a runtime object in the browser. Next.js inlines `NEXT_PUBLIC_*` values directly into the compiled chunks at build time, so you find them by searching the bundle or by inspecting outgoing requests — not by typing `process.env` in the console.

## The Fundamental Problem

**Client-side code cannot keep secrets.** This is a fundamental principle of web security:

- All JavaScript sent to the browser is readable by the user
- Build-time embedding means secrets become part of the code
- No amount of obfuscation can truly hide values in client-side code
- "Security through obscurity" does not work for client-side secrets

## How to Retrieve the Flag

The flag `OSS{public_3nvir0nment_v4ri4bl3}` is leaked through a `NEXT_PUBLIC_*` variable that the checkout page sends as an HTTP header when placing an order.

### A word about what to search for

In a production build, SWC replaces `process.env.NEXT_PUBLIC_PAYMENT_SECRET` with the literal string at compile time and then minifies local identifiers. As a result, the bundle no longer contains the name `NEXT_PUBLIC_PAYMENT_SECRET` — only the leaked value itself remains. Don't search for the variable name, search for value-shaped patterns (long base64 strings, `sk_live_`, `pk_`, JWT, etc.) or watch outgoing requests.

### Steps

1. Navigate to the checkout page (`/checkout`) after adding at least one item to your cart
2. Open DevTools (F12) and go to the **Network** tab
3. Click **Complete Payment** — inspect the outgoing `POST /api/orders` request and look at the request headers. The base64 value `T1NTe3B1YmxpY18zbnZpcjBubWVudF92NHJpNGJsM30=` is sent in the `X-Payment-Auth` header
4. Alternatively, in the **Sources** tab, use global search (`Ctrl+Shift+F` or `Cmd+Option+F` on macOS) and search for the literal value — you'll find it inlined in the compiled chunk for the checkout client component
5. Decode the base64 value in the console: `atob("T1NTe3B1YmxpY18zbnZpcjBubWVudF92NHJpNGJsM30=")`
6. The flag is: **OSS{public_3nvir0nment_v4ri4bl3}**
