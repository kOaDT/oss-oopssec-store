# Malicious File Upload — Stored XSS via SVG

## Overview

The product image upload endpoint accepts files from administrators, validates them only by their reported `Content-Type`, and stores the bytes verbatim. The allowlist includes `image/svg+xml`, which is not a passive image format — SVG is XML, and browsers execute `<script>` and DOM event handlers inside it when the file is rendered as a document.

The vulnerability is amplified on the product detail page: SVG product images are rendered inside an `<object data="…" type="image/svg+xml">` tag, which loads them as full documents and runs any embedded scripts in the user's session.

## Why This Is Dangerous

- **Stored XSS reaches every shopper** — the malicious payload runs for every customer who views the product, not just admins.
- **Trust laundering through "image" upload** — SVG bypasses the mental model that "file upload = static image".
- **`Content-Type` is client-supplied** — header-only checks are spoof-trivial; even genuine image MIME types do not guarantee benign content.
- **Long-lived persistence** — once stored, the file lives on disk and re-runs on every page load until removed.

## Vulnerable Code

The upload handler validates only the `Content-Type` header and writes the bytes to disk:

```typescript
const ALLOWED_CONTENT_TYPES = [
  "image/jpeg",
  "image/png",
  "image/gif",
  "image/webp",
  "image/svg+xml",
];

if (!ALLOWED_CONTENT_TYPES.includes(file.type)) {
  return NextResponse.json({ error: "Invalid file type" }, { status: 400 });
}

const buffer = Buffer.from(await file.arrayBuffer());
const filepath = join(uploadsDir, filename);
await writeFile(filepath, buffer);
```

`file.type` is the value the client claims, not a property of the bytes. Even if it were honest, allowing SVG keeps the door open for `<script>` tags and `onload=` handlers inside the document.

The product detail page renders SVG product images as embedded documents:

```tsx
{
  product.imageUrl.endsWith(".svg") ? (
    <object data={product.imageUrl} type="image/svg+xml">
      <img src={product.imageUrl} alt={product.name} />
    </object>
  ) : (
    <Image src={product.imageUrl} alt={product.name} />
  );
}
```

`<object>` (like `<iframe>` or direct navigation) runs scripts contained in the SVG. `<img src=…>` does not — the same file is "safe" as an image and "executable" as a document.

## Secure Implementation

Three independent controls; apply all of them.

**Inspect the bytes, not the headers.** Detect the format from the file content and only allow strictly passive image types:

```typescript
import { fileTypeFromBuffer } from "file-type";

const buffer = Buffer.from(await file.arrayBuffer());
const detected = await fileTypeFromBuffer(buffer);

const SAFE_MIME_TYPES = ["image/jpeg", "image/png", "image/gif", "image/webp"];

if (!detected || !SAFE_MIME_TYPES.includes(detected.mime)) {
  return NextResponse.json({ error: "Invalid file type" }, { status: 400 });
}
```

If SVG support is genuinely required, sanitize on the server with a hardened SVG-aware sanitizer before storing, and re-render through `<img>`, never `<object>`/`<iframe>`:

```typescript
import DOMPurify from "isomorphic-dompurify";

const safeSvg = DOMPurify.sanitize(buffer.toString("utf-8"), {
  USE_PROFILES: { svg: true, svgFilters: true },
});
```

**Serve uploads from a sandboxed origin.** Either host them on a separate cookie-less domain, or set strict response headers so an XSS in an uploaded file cannot reach the main app's session:

```typescript
headers: [
  { key: "Content-Security-Policy", value: "default-src 'none'" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Content-Disposition", value: "attachment" },
];
```

Keep file names random and divorced from user input; never trust the upload's claimed extension.

## References

- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [CWE-434: Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)
- [PortSwigger — File upload vulnerabilities](https://portswigger.net/web-security/file-upload)
- [OWASP — XSS Filter Evasion / SVG vectors](https://owasp.org/www-community/xss-filter-evasion-cheatsheet)
