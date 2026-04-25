# Insecure Password Reset

## Overview

Password reset tokens must be unguessable — anything less, and the entire reset flow becomes a public-facing account takeover endpoint. Building tokens from values an attacker can predict (email, current time, sequential counters) means the token can be derived without ever owning the victim's mailbox.

In this challenge, the forgot-password endpoint computes the reset token as `MD5(email + unix_timestamp)` and even returns the exact `requestedAt` ISO timestamp in the response, handing the attacker every input they need to forge the token themselves.

## Why This Is Dangerous

- **Account takeover without email access** — knowing only a target email is enough to forge a valid reset token.
- **Privilege escalation** — admin accounts can be hijacked the same way, with no extra steps.
- **No rate limiting** — unlimited reset requests let attackers grind timestamps, fingerprint accounts, or drown logs.
- **Generic appearance** — the API response looks innocuous, so the leak is easy to overlook in code review.

## Vulnerable Code

```typescript
const now = new Date();
const requestedAt = now.toISOString();
const timestamp = Math.floor(now.getTime() / 1000);

const user = await prisma.user.findUnique({ where: { email } });

if (user) {
  const token = hashMD5(email + timestamp);
  const expiresAt = new Date(now.getTime() + 60 * 60 * 1000);

  await prisma.passwordResetToken.deleteMany({ where: { email } });
  await prisma.passwordResetToken.create({
    data: { token, email, expiresAt },
  });
}

return NextResponse.json({
  message: "If an account with that email exists, ...",
  requestedAt,
});
```

Two compounding bugs:

1. The token is fully determined by `email` and `timestamp`. MD5 is fast and the search space — at most one Unix second — is tiny.
2. The response leaks `requestedAt`, eliminating even that one-second guess.

## Secure Implementation

Generate tokens with a cryptographically secure RNG, store only their hash, and stop leaking timing data:

```typescript
import crypto from "crypto";

const rawToken = crypto.randomBytes(32).toString("hex");
const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");
const expiresAt = new Date(Date.now() + 30 * 60 * 1000);

await prisma.passwordResetToken.deleteMany({ where: { email } });
await prisma.passwordResetToken.create({
  data: { token: tokenHash, email, expiresAt },
});

// `rawToken` is what goes in the email link; the DB only ever holds the hash.

return NextResponse.json({
  message: "If an account with that email exists, ...",
});
```

Additional controls that should be in place before the reset flow ships:

- **Short-lived tokens** — 15–30 minutes, single-use, invalidated on any password change.
- **Rate limiting** — per-email and per-IP, with exponential backoff.
- **Constant-shape responses** — return the same body whether or not the email exists, with no timing or content side channels.
- **Re-authentication on success** — invalidate all existing sessions when a reset succeeds.

## References

- [OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
- [CWE-640: Weak Password Recovery Mechanism for Forgotten Password](https://cwe.mitre.org/data/definitions/640.html)
- [CWE-330: Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)
- [CWE-209: Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html)
