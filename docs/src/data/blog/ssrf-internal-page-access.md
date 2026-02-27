---
author: kOaDT
authorGithubUrl: https://github.com/kOaDT
authorGithubAvatar: https://avatars.githubusercontent.com/u/17499022?v=4
pubDatetime: 2026-01-17T10:00:00Z
title: "Server-Side Request Forgery: Accessing Internal Pages via Support Form"
slug: ssrf-internal-page-access
draft: false
tags:
  - writeup
  - ssrf
  - ctf
description: Exploiting a server-side request forgery vulnerability in OopsSec Store's support form to access restricted internal pages.
---

The OopsSec Store has a support form with a "screenshot URL" field. The backend fetches whatever URL you give it and shows you the response. Point it at `localhost` and you can read internal pages that are supposed to be off-limits.

## Table of contents

## Lab setup

The lab requires Node.js. From an empty directory:

```bash
npx create-oss-store oss-store
cd oss-store
npm start
```

Head to `http://localhost:3000`.

## Target identification

There's a Contact Support page at `http://localhost:3000/support` with a few fields: email, title, description, and an optional screenshot URL.

![Support form with screenshot URL field](../../assets/images/ssrf-internal-page-access/support-form.webp)

The screenshot URL field lets users attach visual context to their request. Submit the form and the app shows a recap with a rendered preview of whatever that URL points to. So the server is fetching the URL on your behalf and returning the content directly.

## Exploitation

### Step 1: Confirm the server is doing the fetching

Submit a support request with a public URL to make sure it's the server making the request, not your browser:

1. Go to `http://localhost:3000/support`
2. Fill in the form:
   - Email: `test@test.com`
   - Title: `Test`
   - Description: `Testing support`
   - Screenshot URL: `https://example.com`
3. Submit

The recap page shows the raw HTML and CSS from `example.com`. The server is the one fetching.

![Support recap showing example.com content](../../assets/images/ssrf-internal-page-access/example-com-response.webp)

### Step 2: Find something internal

Now that the server will fetch any URL we give it, we need a target. Running a wordlist scan with `ffuf` or `gobuster` turns up an `/internal` endpoint that returns a 302. Visiting `http://localhost:3000/internal` in the browser just bounces you back to the homepage -- the page exists but won't let you in directly.

That redirect blocks browser requests. But server-side requests from `localhost` don't go through the same path.

### Step 3: Exploit the SSRF

Submit another support request, this time pointing at the internal page:

1. Go to `http://localhost:3000/support`
2. Fill in the form:
   - Email: `test@test.com`
   - Title: `Internal access test`
   - Description: `Testing SSRF`
   - Screenshot URL: `http://localhost:3000/internal`
3. Submit

### Step 4: Get the flag

The recap page renders the internal page's HTML instead of redirecting. The server-side request bypasses the restriction because it originates from `localhost`.

![Support recap displaying internal page content with flag](../../assets/images/ssrf-internal-page-access/internal-page-flag.webp)

```
OSS{s3rv3r_s1d3_r3qu3st_f0rg3ry}
```

## Vulnerable code analysis

Here's what happens when you submit the form:

1. The API reads `screenshotUrl` from your input
2. Calls `fetch()` on it
3. Sends the response straight back to you

No validation on the URL. Nothing stops you from pointing it at `localhost`, `127.0.0.1`, or any private IP range.

## Remediation

Check the protocol first. Only allow HTTP and HTTPS:

```typescript
const url = new URL(screenshotUrl);
if (!["http:", "https:"].includes(url.protocol)) {
  throw new Error("Invalid protocol");
}
```

Block internal addresses:

```typescript
const BLOCKED_HOSTS = ["localhost", "127.0.0.1", "0.0.0.0"];
const PRIVATE_RANGES = [
  /^10\./,
  /^172\.(1[6-9]|2[0-9]|3[01])\./,
  /^192\.168\./,
];

if (
  BLOCKED_HOSTS.includes(url.hostname) ||
  PRIVATE_RANGES.some(range => range.test(url.hostname))
) {
  throw new Error("Internal addresses are not allowed");
}
```

Better yet, allowlist the domains you actually expect:

```typescript
const ALLOWED_DOMAINS = ["cdn.example.com", "images.example.com"];
if (!ALLOWED_DOMAINS.includes(url.hostname)) {
  throw new Error("Domain not allowed");
}
```

Don't return raw fetched content either. Store metadata or sanitize the response before showing it to anyone.
