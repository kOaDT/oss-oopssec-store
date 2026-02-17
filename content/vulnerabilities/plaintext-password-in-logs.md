# Plaintext Password Exposure in Server Logs

## Overview

This vulnerability demonstrates how sensitive credentials can leak through server-side logging combined with an insufficiently protected internal monitoring interface. A forgotten debug statement in the login route writes plaintext passwords to a log file, and a hidden SIEM dashboard exposes those logs to anyone who discovers its URL and guesses its hardcoded credentials.

## Why This Is Dangerous

### Plaintext Credential Logging

Passwords must never appear in application logs. Even if logs are considered "internal," they are routinely accessed by:

1. **Operations engineers** during debugging
2. **Log aggregation platforms** (ELK, Splunk, Datadog) where access controls may be broader than expected
3. **Backup systems** that archive log files to less secure storage
4. **Attackers** who gain partial access to the infrastructure

### Hidden Does Not Mean Secure

Relying on obscurity (an unlisted URL) instead of proper authentication and authorization is a well-known anti-pattern. Standard directory enumeration tools discover paths like `/monitoring/siem` within seconds using common wordlists.

### Weak Credentials on Internal Tools

The SIEM interface is protected by trivially guessable credentials (`root:admin`). In a real-world scenario, internal tools stored in a database with weak default passwords are equally vulnerable — attackers routinely try common credential pairs against any login form they discover.

## The Vulnerability

The application has three compounding weaknesses:

1. **Global log capture** — `instrumentation.ts` monkey-patches `console.*` methods to append every server-side log call to `logs/app.log`.
2. **Forgotten debug statement** — The login route at `/api/auth/login` contains a `console.log` that outputs the email, plaintext password, and an internal flag on every login attempt.
3. **Exposed internal tool** — A SIEM dashboard at `/monitoring/siem` reads and displays the log file, protected only by hardcoded credentials.

## Exploitation

### How to Retrieve the Flag

To retrieve the flag `OSS{pl41nt3xt_p4ssw0rd_1n_l0gs}`:

1. Submit any login attempt on `/login` (valid or invalid credentials)
2. Discover `/monitoring/siem` using directory enumeration (e.g., gobuster, dirsearch, feroxbuster)
3. Authenticate with `root` / `admin`
4. Search the log table for `[auth] login attempt` entries
5. The flag appears in the `message` column alongside the plaintext password

### Secure Implementation

```typescript
// ❌ VULNERABLE — Plaintext credentials in logs
console.log("[auth] login attempt", { email, password, flag: LOGIN_FLAG });

// ✅ SECURE — Log only non-sensitive identifiers
logger.info("Login attempt", { email, success: false });
```

```typescript
// ❌ VULNERABLE — Hardcoded credentials, no real access control
const SIEM_USER = "root";
const SIEM_PASS = "admin";

// ✅ SECURE — Proper authentication, network-level restrictions
// - Use SSO or OIDC for internal tools
// - Restrict to private network / VPN
// - Apply role-based access control
// - Audit all access to monitoring systems
```

## References

- [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
- [CWE-532: Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [OWASP Top 10 - Security Misconfiguration](https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/)
