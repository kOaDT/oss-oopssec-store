# Session Fixation & Weak Support-Session Management

## Overview

This vulnerability is a session-fixation flaw built on top of a mass-assignment bug in a "support access" feature. The endpoint that mints support tokens for the authenticated user also accepts an `email` field in the request body and uses it as the target account, so any logged-in user can issue a long-lived support token for any other account — including the admin's. The token, once issued, is then accepted by a separate login endpoint that promotes its bearer to a full authenticated session.

A long token lifetime (365 days) and ineffective revocation (the validator does not check the `revoked` flag) compound the impact.

## Why This Is Dangerous

- **Cross-account session fixation** — anyone with a regular account can mint a session token for anyone else.
- **Privilege escalation** — the admin account is reachable as long as its email is known.
- **Persistent access** — 365-day tokens survive password changes; "revoke" only flips a database column the validator ignores.
- **Audit gaps** — these tokens look like legitimate support sessions in logs.

## Vulnerable Code

The token-creation endpoint reads the target account from the request body, not the session:

```typescript
export const POST = withAuth(async (request, _context, user) => {
  const body = await request.json().catch(() => ({}));

  const targetEmail = body.email || user.email;

  const targetUser = await prisma.user.findUnique({
    where: { email: targetEmail },
    select: { id: true, email: true, role: true },
  });

  if (!targetUser) {
    return NextResponse.json({ error: "User not found" }, { status: 404 });
  }

  const token = generateSecureToken();
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + 365);

  await prisma.supportAccessToken.create({
    data: {
      token,
      userId: targetUser.id,
      email: targetUser.email,
      expiresAt,
    },
  });
});
```

The validator that exchanges the support token for a session does not check `revoked`:

```typescript
const supportToken = await prisma.supportAccessToken.findUnique({
  where: { token },
});

if (supportToken.expiresAt < new Date()) {
  return NextResponse.json({ error: "Token expired" }, { status: 401 });
}

const authToken = createWeakJWT({
  id: supportToken.user.id,
  email: supportToken.user.email,
  role: supportToken.user.role,
  supportAccess: true,
});
```

## Secure Implementation

Three independent fixes; apply all of them.

**Bind the operation to the authenticated user.** Stop reading the target email from the body — derive it from the session, full stop:

```typescript
const targetEmail = user.email;
```

Sensitive fields like `email`, `userId`, or `role` should never be writable through a generic JSON body. If admins legitimately need to issue tokens on behalf of others, that is a separate, authorization-checked, audited endpoint.

**Make tokens short-lived and revocable.** Cap lifetime in hours, and check `revoked` on every validation. Any token issued for an admin or any role-elevation context should require step-up auth (password or MFA confirmation):

```typescript
expiresAt.setHours(expiresAt.getHours() + 12);

if (supportToken.revoked) {
  return NextResponse.json({ error: "Token revoked" }, { status: 401 });
}
```

**Rate-limit and audit.** Throttle the token-creation endpoint per user and per IP, and emit an audit event on every issuance and use, indexed by both the issuer and the target account.

## References

- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [CWE-384: Session Fixation](https://cwe.mitre.org/data/definitions/384.html)
- [CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)
- [OWASP Top 10 — A01:2021 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
