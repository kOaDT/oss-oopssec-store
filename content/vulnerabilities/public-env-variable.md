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
- Type `process.env` to see all exposed variables
- View the page source and search for the variable name
- Inspect the JavaScript bundle files in the Network tab

## The Fundamental Problem

**Client-side code cannot keep secrets.** This is a fundamental principle of web security:

- All JavaScript sent to the browser is readable by the user
- Build-time embedding means secrets become part of the code
- No amount of obfuscation can truly hide values in client-side code
- "Security through obscurity" does not work for client-side secrets

## How to Retrieve the Flag

The flag `OSS{public_3nvir0nment_v4ri4bl3}` is exposed through a `NEXT_PUBLIC_*` variable:

1. Navigate to the checkout page
2. Open the browser's developer console (F12)
3. Search: `process.env.NEXT_PUBLIC_PAYMENT_SECRET` into Sources tab
4. The value `T1NTe3B1YmxpY18zbnZpcjBubWVudF92NHJpNGJsM30=` will be displayed
5. Decode the base64 value: `atob("T1NTe3B1YmxpY18zbnZpcjBubWVudF92NHJpNGJsM30=")`
6. The flag is: **OSS{public_3nvir0nment_v4ri4bl3}**
