# XML External Entity (XXE) Injection in Supplier Order Import

## Overview

This vulnerability demonstrates how an insecure XML parser configuration can allow an attacker to read arbitrary files from the server. The admin panel includes a supplier order import feature that accepts XML input and resolves external entity declarations, including those referencing the local file system.

## Why This Is Dangerous

### Arbitrary File Read

XXE attacks allow an attacker to read any file the application process has access to. This includes:

1. **Application configuration files** containing API keys, database credentials, and secrets
2. **System files** such as `/etc/passwd` or `/etc/hostname`
3. **Source code** and internal documentation
4. **Other sensitive data** stored on the file system

### Server-Side Processing Trust

The XML specification supports Document Type Definitions (DTDs) and entity declarations that can reference external resources. When a parser resolves these entities without restriction, user-controlled input can instruct the server to fetch and embed the contents of arbitrary URIs.

## The Vulnerability

The supplier order import endpoint at `/api/admin/suppliers/import-order` accepts raw XML from the request body. Before parsing the XML structure, a pre-processing step resolves all `<!ENTITY ... SYSTEM "...">` declarations by reading the referenced files and substituting their contents into the XML document.

This simulates a real-world misconfiguration where:

- DTD processing is enabled
- External entity resolution is not disabled
- User-controlled XML is parsed without sanitization

The parsed fields — including `notes` — are reflected in the API response, allowing the resolved file contents to be exfiltrated.

## Exploitation

### Prerequisites

This vulnerability requires admin access to the application. Admin access can be obtained through other vulnerabilities such as JWT secret forgery or mass assignment during signup.

### How to Retrieve the Flag

1. Gain admin access to the application
2. Navigate to `/admin/suppliers`
3. Submit a crafted XML payload with an external entity declaration pointing to a file on the server:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE order [
  <!ENTITY xxe SYSTEM "file://flag-xxe.txt">
]>
<order>
  <supplierId>SUP-001</supplierId>
  <orderId>PO-2026-0001</orderId>
  <total>0</total>
  <notes>&xxe;</notes>
</order>
```

4. The `notes` field in the response will contain the file contents, which includes the flag

### Secure Implementation

```typescript
// VULNERABLE — resolves external entities from user input
function resolveExternalEntities(xml: string): string {
  // Reads files referenced in SYSTEM entity declarations
  // and substitutes their contents into the XML
}

// SECURE — disable DTD processing entirely
const parser = new XMLParser({
  processEntities: false,
  // Do not resolve external entity declarations
});
// Additionally: strip or reject any DOCTYPE declarations before parsing
```

## References

- [CWE-611: Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)
- [OWASP XML External Entity (XXE) Processing](<https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing>)
- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
