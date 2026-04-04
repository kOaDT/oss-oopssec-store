# Information Disclosure via API Error Messages

## Overview

This vulnerability demonstrates how overly verbose error messages in API responses can leak sensitive information. In this case, the user data export feature inadvertently exposes sensitive system data when an error occurs due to invalid input.

## Why This Is Dangerous

### Verbose Error Messages

When an application returns detailed technical error messages to users, it creates several security risks:

1. **Sensitive data exposure** - Error messages might inadvertently reveal actual sensitive data
2. **Configuration leakage** - Debug information can expose internal configuration and secrets
3. **Attack surface mapping** - Knowledge of the system helps craft targeted attacks
4. **Schema disclosure** - Attackers learn the internal structure of the application

## The Vulnerability

In this application, the user data export endpoint (`/api/user/export`) allows users to select which fields to export. When invalid field names are provided, the endpoint returns an error with "debug information" that includes system diagnostics.

## Exploitation

### How to Retrieve the Flag

To retrieve the flag `OSS{1nf0_d1scl0sur3_4p1_3rr0r}`, follow these steps:

1. Log in to the application (e.g., as alice@example.com / iloveduck)
2. Navigate to the Profile page (`/profile`) and click on the "Data Export" tab
3. Notice the form uses checkboxes with only valid fields -- you can't submit invalid input through the UI
4. Bypass the frontend and call the API directly with an invalid field name
5. Observe the error response which includes debug information
6. In the `systemDiagnostics.featureFlags` field, find the flag

**Using curl:**

```bash
# First, log in and save cookies
curl -c cookies.txt -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"iloveduck"}'

# Then hit the export endpoint with an invalid field
curl -b cookies.txt -X POST http://localhost:3000/api/user/export \
  -H "Content-Type: application/json" \
  -d '{"format":"json","fields":["invalid_field"]}'
```

### Secure Implementation

```typescript
// ❌ VULNERABLE - Exposes sensitive data in error responses
catch (error) {
  const diagnostics = await getSystemDiagnostics(); // Includes secrets!
  return NextResponse.json({
    error: "Export failed",
    debug: { systemDiagnostics: diagnostics },
  }, { status: 500 });
}

// ✅ SECURE - Generic error message, no debug info in production
catch (error) {
  console.error("Export error:", error); // Log internally only
  return NextResponse.json(
    { error: "An error occurred processing your request" },
    { status: 500 }
  );
}

// ✅ SECURE - Validate input before processing
const invalidFields = requestedFields.filter(f => !ALLOWED_FIELDS.includes(f));
if (invalidFields.length > 0) {
  return NextResponse.json(
    { error: "Invalid fields specified", allowedFields: ALLOWED_FIELDS },
    { status: 400 }
  );
  // No debug information, no system diagnostics
}
```

## References

- [OWASP Top 10 - Security Misconfiguration](https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/)
- [CWE-209: Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [PortSwigger - Information Disclosure](https://portswigger.net/web-security/information-disclosure)
