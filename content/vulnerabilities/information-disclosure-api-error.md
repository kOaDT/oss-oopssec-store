# Information Disclosure via API Error Messages

## Overview

Verbose error responses expose internal state that callers were never meant to see. When an endpoint catches an exception or rejects malformed input, it is tempting to attach a "debug" payload with stack traces, environment metadata, configuration, or feature-flag values to help during development — and just as easy to forget that field is shipped in production.

In this challenge, the user data export endpoint returns a `debug.systemDiagnostics` block on validation errors, and that block reads from internal data sources that include sensitive values.

## Why This Is Dangerous

- **Direct secret leakage** — diagnostics fields can carry feature-flag values, tokens, or build metadata that should never reach a client.
- **Schema disclosure** — listing allowed fields, internal types, or error stacks tells an attacker how to shape future probes.
- **Environment fingerprinting** — Node version, environment name, ORM version, and DB connection state map the attack surface for free.
- **Trust-boundary inversion** — debug branches built for developers run with full server privileges in production.

## Vulnerable Code

The export endpoint enriches its 400-response with a system diagnostics object that reads internal records:

```typescript
async function getSystemDiagnostics() {
  const diagnostics: Record<string, unknown> = {
    timestamp: new Date().toISOString(),
    nodeVersion: process.version,
    environment: process.env.NODE_ENV,
  };

  diagnostics.database = {
    connected: true,
    version: "Prisma Client v6.19.1",
  };

  const flag = await prisma.flag.findUnique({
    where: { slug: "information-disclosure-api-error" },
  });
  diagnostics.featureFlags = flag?.flag;

  return diagnostics;
}

if (invalidFields.length > 0) {
  const diagnostics = await getSystemDiagnostics();
  return NextResponse.json(
    {
      error: "Invalid field names in export request",
      invalidFields,
      allowedFields: ALLOWED_USER_FIELDS,
      debug: {
        message: "Export failed due to invalid field specification",
        requestedFields,
        systemDiagnostics: diagnostics,
      },
    },
    { status: 400 }
  );
}
```

Anything `getSystemDiagnostics` decides to read — including secrets pulled by mistake from the same `Flag` table that drives unrelated app data — flows straight to the response body.

## Secure Implementation

Return the smallest response that lets a legitimate caller fix their request, and log the rest server-side:

```typescript
if (invalidFields.length > 0) {
  return NextResponse.json(
    {
      error: "Invalid field names in export request",
      invalidFields,
      allowedFields: ALLOWED_USER_FIELDS,
    },
    { status: 400 }
  );
}
```

For unexpected errors, log internally with full context and return a generic message:

```typescript
} catch (error) {
  logger.error({ err: error, route: "/api/user/export" }, "Export failed");
  return NextResponse.json(
    { error: "An error occurred processing your request" },
    { status: 500 },
  );
}
```

The general principle is to treat error responses as part of the API contract: never include data from sources the caller is not authorized to read, and never let "debug" fields ride along into production. A correlation ID in the response is enough to map a user-facing error back to detailed server logs.

## References

- [OWASP Top 10 — A02:2025 Security Misconfiguration](https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/)
- [CWE-209: Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [PortSwigger — Information Disclosure](https://portswigger.net/web-security/information-disclosure)
