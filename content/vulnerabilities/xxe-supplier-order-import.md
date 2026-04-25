# XML External Entity (XXE) — Supplier Order Import

## Overview

XML parsers that resolve external entity declarations turn an XML body into an arbitrary file-read primitive. A `<!ENTITY xxe SYSTEM "file:///…">` declaration tells the parser to fetch the referenced URI and substitute its contents into the document; if any field of the parsed document is reflected back to the caller, the file's contents come along with it.

In this challenge, the admin supplier-order import endpoint parses the request body with `libxmljs2` and the options `noent: true, dtdload: true`, which together enable both DTD loading and entity expansion. The parsed `notes` field is reflected in the API response.

## Why This Is Dangerous

- **Arbitrary local file read** — anything readable by the application user (config, secrets, source) can be exfiltrated.
- **Credential leakage** — `.env`, cloud SDK config, deploy tokens — all routinely sit on disk where the app runs.
- **Server-side request forgery** — `SYSTEM` URIs can be HTTP(S), letting attackers pivot to internal endpoints from the parser context.
- **Denial of service** — entity-expansion attacks ("billion laughs") can exhaust memory and CPU before any authorization is checked.

## Vulnerable Code

```typescript
const rawXml = await request.text();

const doc = libxmljs.parseXmlString(rawXml, {
  noent: true,
  dtdload: true,
});

const root = doc.root();
// ...
const notes = (root.get("notes") as libxmljs.Element | null)?.text()?.trim() || "";

const supplierOrder = await prisma.supplierOrder.create({
  data: { supplierId, orderId, total, notes: notes || null },
});

return NextResponse.json({
  message: "Supplier order imported successfully.",
  order: { ..., notes: supplierOrder.notes },
});
```

`noent: true` substitutes entity references with their resolved values; `dtdload: true` lets the parser load DTDs (which is where `<!ENTITY ...>` declarations live). With both on, any `SYSTEM "file:///…"` declaration in the request body is followed and the contents flow into the parsed XML.

## Secure Implementation

Disable DTD loading and external entity resolution. With `libxmljs2`, that means dropping both options and rejecting any document that contains a `<!DOCTYPE>` declaration:

```typescript
if (/<!DOCTYPE/i.test(rawXml)) {
  return NextResponse.json(
    { error: "DOCTYPE declarations are not permitted" },
    { status: 400 }
  );
}

const doc = libxmljs.parseXmlString(rawXml);
```

Whatever XML library you use, the secure default is the same: no DTD loading, no external entity resolution, no XInclude. The OWASP cheat sheet lists the explicit flags for every common parser.

If the use case can afford it, prefer a non-XML format (JSON, CSV) for inputs that come from outside the trust boundary — the safest XXE is the one that cannot be triggered because the parser is not in the request path.

A few additional controls:

- **Hard size limits and parse timeouts** to defeat billion-laughs and quadratic-blowup variants.
- **Strict schema validation** on the parsed document to catch unexpected structures early.
- **Avoid reflecting parsed fields back to callers.** Return a structural confirmation (IDs, timestamps), not the raw values, so file contents cannot ride out in the response.

## References

- [CWE-611: Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)
- [OWASP — XML External Entity (XXE) Processing](<https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing>)
- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [PortSwigger — XML external entity (XXE) injection](https://portswigger.net/web-security/xxe)
