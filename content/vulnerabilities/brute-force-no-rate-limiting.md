# Brute Force — No Rate Limiting

## Overview

The login endpoint accepts unlimited authentication attempts from any source. With no rate limiting, account lockout, CAPTCHA, or progressive backoff, an attacker can throw an entire wordlist at any known email address until one password matches. The fast MD5-based hash on the server side makes the attack cheap end-to-end.

This challenge pairs the missing rate limit with email addresses leaked elsewhere in the application, so the attacker only has to guess the password.

## Why This Is Dangerous

- **Password guessing at scale** — common-password and credential-stuffing attacks succeed against weak passwords.
- **Account takeover** — every account whose owner reused a leaked password becomes reachable.
- **Account enumeration** — distinct error messages for "user not found" vs. "invalid password" let attackers harvest valid emails.
- **Resource exhaustion** — unbounded login traffic can be turned into a cheap denial-of-service vector.

## Vulnerable Code

```typescript
export async function POST(request: Request) {
  const body = await request.json();
  const { email, password } = body;

  const hashedPassword = hashMD5(password);
  const user = await prisma.user.findUnique({ where: { email } });

  if (!user) {
    return NextResponse.json({ error: "Invalid credentials" }, { status: 401 });
  }

  if (user.password !== hashedPassword) {
    return NextResponse.json({ error: "Invalid password" }, { status: 401 });
  }

  // ... issue session token
}
```

There is no per-IP, per-account, or global throttling. The two distinct error messages also make user enumeration trivial.

## Secure Implementation

Apply layered defenses; no single control is sufficient.

In a Next.js Route Handler, throttle each (IP, email) pair through a shared store — Redis with `@upstash/ratelimit`, or a `LoginAttempt` table when a database is already in the request path:

```typescript
import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";

const loginLimiter = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(5, "15 m"),
});

export async function POST(request: Request) {
  const ip = request.headers.get("x-forwarded-for") ?? "unknown";
  const { email } = await request.json();
  const { success } = await loginLimiter.limit(`login:${ip}:${email}`);

  if (!success) {
    return NextResponse.json(
      { error: "Too many login attempts. Please try again later." },
      { status: 429 }
    );
  }
  // ... continue with credential check
}
```

Combine with:

- **Account lockout** — increment a `failedLoginAttempts` counter and reject (HTTP 429) once a threshold is hit, with a cooldown.
- **Generic error messages** — return the same response for unknown email and wrong password to defeat enumeration.
- **Strong password hashing** — replace MD5 with bcrypt/argon2 so each guess costs the attacker meaningfully more.
- **CAPTCHA** — gate the form after a few failures.
- **MFA** — make a stolen password insufficient on its own.
- **Monitoring** — alert on bursts of failed logins from a single IP or against a single account.

## References

- [OWASP — Brute Force Attack](https://owasp.org/www-community/attacks/Brute_force_attack)
- [OWASP — Blocking Brute Force Attacks](https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks)
- [CWE-307: Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)
- [NIST SP 800-63B — Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
