# Mass Assignment

## Overview

Mass assignment occurs when an endpoint copies fields from the request body straight into a database record without restricting which fields the caller is allowed to set. Sensitive attributes that should be controlled by the server (role, permissions, balance, ownership) become writable from the outside.

In this challenge, the signup endpoint forwards an optional `role` field from the request body into the new user's record, letting any anonymous caller create an account with `role: "ADMIN"`.

## Why This Is Dangerous

- **Privilege escalation at registration** — anonymous traffic can mint admin accounts.
- **Implicit trust in client shape** — every new field the model gains becomes silently writable from the API.
- **Bypasses business logic** — checks placed on dedicated "role change" endpoints are irrelevant if signup itself accepts roles.
- **Hard to audit after the fact** — privilege escalations look identical to legitimate signups in logs.

## Vulnerable Code

```typescript
const userData: {
  email: string;
  password: string;
  addressId: string;
  role?: UserRole;
} = {
  email,
  password: hashedPassword,
  addressId: defaultAddress.id,
};

if (body.role) {
  userData.role = body.role as UserRole;
}

const user = await prisma.user.create({ data: userData });
```

`body.role` comes straight from the request and is forwarded unchecked. The Prisma model has a `role` column, so the assignment succeeds. There is no allowlist of writable fields, no role validation, and no separation between "signup" and "admin-only role assignment".

## Secure Implementation

Build the create payload from an explicit allowlist. Never spread or forward the request body:

```typescript
const { email, password } = body;

const user = await prisma.user.create({
  data: {
    email,
    password: hashedPassword,
    addressId: defaultAddress.id,
    role: "CUSTOMER",
  },
});
```

If the API must accept structured input, validate it with a schema and ignore everything else:

```typescript
import { z } from "zod";

const SignupSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
});

const { email, password } = SignupSchema.parse(body);
```

Privileged fields like `role` belong on a separate, authenticated, admin-only endpoint. The general principle: writable fields are an allowlist, not a denylist, and the allowlist lives next to the data model — not next to the user input.

## References

- [OWASP API Security Top 10 — API6:2019 Mass Assignment](https://owasp.org/API-Security/editions/2019/en/0xa6-mass-assignment/)
- [OWASP Mass Assignment Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
- [CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)
