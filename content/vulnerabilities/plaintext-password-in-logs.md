# Plaintext Passwords in Server Logs

## Overview

Logging is a security control until it becomes an attack surface. When request handlers serialize sensitive fields directly into log entries — even with a "warn" or "debug" level — those fields end up everywhere logs go: disk, log shippers, archive buckets, ops dashboards, third-party SaaS log indexers. Each of those is a fresh place where a password can be read by someone who has no business reading it.

In this challenge, the login route writes the submitted email and plaintext password into a structured log line on every attempt, and an "internal" SIEM dashboard surfaces those logs to anyone who finds its URL and guesses its hardcoded credentials.

## Why This Is Dangerous

- **Credential exposure on every login** — passwords are written to disk in clear text on success _and_ failure.
- **Logs travel further than expected** — log files are mirrored to backup, observability, and SIEM systems with broader access than the app itself.
- **Compliance impact** — PCI-DSS, GDPR, ISO 27001, SOC 2 all explicitly forbid logging credentials.
- **Obscurity is not access control** — unlinked monitoring URLs are discovered by routine directory enumeration in seconds.
- **Hardcoded internal credentials** — built-in admin/admin-style credentials on internal tools turn discovery into compromise.

## Vulnerable Code

```typescript
logger.warn(
  {
    email,
    password,
    flag: LOGIN_FLAG,
    route: "/api/auth/login",
    action: "login_attempt",
  },
  `[auth] login attempt email=${email} password=${password} flag=${LOGIN_FLAG}`
);
```

The password is written twice — once as a structured field, once interpolated into the message string. Even if downstream sinks redact known field names, the interpolated copy bypasses the redaction.

The internal monitoring dashboard amplifies the exposure with hardcoded credentials:

```typescript
const SIEM_USER = "root";
const SIEM_PASS = "admin";
```

## Secure Implementation

Never log secrets, and treat internal tools as production surface area.

**Strip sensitive fields before logging.** Log identifiers, not credentials, and never interpolate request bodies:

```typescript
logger.info(
  { route: "/api/auth/login", email, success },
  "Login attempt processed"
);
```

For frameworks that auto-serialize request objects (pino, winston, etc.), configure a redaction list at the logger level so a careless `logger.info({ req })` cannot leak a body field:

```typescript
const logger = pino({
  redact: {
    paths: ["password", "*.password", "headers.authorization", "*.token"],
    censor: "[REDACTED]",
  },
});
```

**Guard internal tools with real authentication.** Replace hardcoded credentials with an SSO/OIDC flow, scope access through role-based authorization, restrict the network path (VPN, private subnet, IP allowlist), and audit every access to the log surface.

**Rotate any leaked credential.** Once a password has touched a log, it must be considered compromised; force resets on every account that may have been affected.

## References

- [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
- [CWE-532: Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [OWASP Top 10 — A05:2021 Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
