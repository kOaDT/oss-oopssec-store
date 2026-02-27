---
author: kOaDT
authorGithubUrl: https://github.com/kOaDT
authorGithubAvatar: https://avatars.githubusercontent.com/u/17499022?v=4
pubDatetime: 2026-01-23T19:48:00Z
title: "Stored XSS in Product Reviews"
slug: stored-xss-product-reviews
draft: false
tags:
  - writeup
  - xss
  - ctf
description: Exploiting stored cross-site scripting in OopsSec Store's product review functionality to execute JavaScript in every visitor's browser.
---

The product reviews feature in OopsSec Store doesn't sanitize input. At all. You can drop a `<script>` tag into a review, it gets saved to the database, and it runs in every visitor's browser. Here's how to go from a comment box to stealing a flag.

## Table of contents

## Vulnerability overview

Users can submit reviews on product pages. Those reviews get stored in the database and displayed back when someone loads the page. The problem: the server saves whatever you type without sanitization, and the frontend renders it as raw HTML. If your "review" happens to be a script tag, the browser will execute it.

Here's what happens:

1. Submit a review containing JavaScript
2. The backend stores it as-is
3. Any user who visits the product page gets the review injected into their DOM
4. The browser executes the script in that user's session

## Locating the attack surface

Go to any product page and scroll down to the reviews section. There's a list of existing reviews and a form to add your own.

![Product reviews section showing existing comments and submission form](../../assets/images/stored-xss-product-reviews/reviews-section.webp)

Submitting a review sends a POST to `/api/products/[id]/reviews`. The backend stores the content directly, the frontend renders it without escaping.

## Exploitation

### Discovering the target

Looking through existing reviews, there's a comment from "Mr. Robot":

> "Heard the devs left some old flags lying around at the root... files that say exactly what they are. Classic mistake!"

A flag file at the application root. Given the naming convention, `/xss-flag.txt` is the obvious guess.

### Crafting the payload

First, confirm the XSS works:

```html
<script>
  alert("XSS");
</script>
```

If that pops an alert, input is being executed as code.

Now the real payload -- fetch the flag and display it:

```html
<script>
  fetch("/xss-flag.txt")
    .then(r => r.text())
    .then(flag => alert("Flag: " + flag));
</script>
```

### Executing the attack

1. Open any product page in OopsSec Store
2. Scroll to the reviews section
3. Paste the payload into the review textarea
4. Click Submit

The API saves it as a regular review. No validation, no filtering.

### Triggering the vulnerability

Refresh the page. The malicious review loads from the database, gets injected into the DOM, and the browser sees the `<script>` tag and runs it.

The script fetches `/xss-flag.txt` (same-origin, no CORS issues) and pops the flag:

```
OSS{cr0ss_s1t3_scr1pt1ng_xss}
```

Anyone who visits this product page from now on triggers the same script.

## Vulnerable code analysis

### Server-side: no input sanitization

The API endpoint stores whatever the user sends:

```typescript
const review = await prisma.review.create({
  data: {
    productId: id,
    content: content.trim(), // No sanitization performed
    author,
  },
});
```

`trim()` strips whitespace. HTML and JavaScript pass through untouched.

### Client-side: raw HTML injection

The frontend injects review content into the DOM through a ref:

```tsx
<div
  ref={el => {
    reviewRefs.current[review.id] = el; // Raw HTML injection
  }}
  className="text-slate-700 dark:text-slate-300"
/>
```

This sidesteps React's built-in XSS protection. Normally React escapes anything passed as a JSX expression, but setting HTML through a ref bypasses that.

## Remediation

### Server-side sanitization

Strip dangerous HTML before it hits the database. DOMPurify handles this:

```typescript
import DOMPurify from "isomorphic-dompurify";

const review = await prisma.review.create({
  data: {
    productId: id,
    content: DOMPurify.sanitize(content.trim()),
    author,
  },
});
```

Script tags and event handlers get removed before anything is saved.

### Client-side safe rendering

Let React do what it's designed to do -- escape HTML:

```tsx
<div className="text-slate-700 dark:text-slate-300">{review.content}</div>
```

Passing content as a JSX expression means React escapes HTML entities automatically.

Apply both fixes. Server-side sanitization stops malicious content from entering the database. Client-side escaping stops it from executing even if something slips through. Either one blocks this attack on its own, but XSS is one of those things where you really want both layers.
