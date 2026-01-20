---
author: kOaDT
pubDatetime: 2026-01-15T10:00:00Z
title: "Mass Assignment: Admin Privilege Escalation via Signup"
slug: mass-assignment-admin-privilege-escalation
draft: false
tags:
  - writeup
  - mass-assignment
  - ctf
description: Exploiting a mass assignment vulnerability in OopsSec Store's signup endpoint to create an account with administrator privileges.
---

This writeup demonstrates how to exploit a mass assignment vulnerability in OopsSec Store's user registration endpoint. By injecting an unauthorized field into the signup request, an attacker can create an account with administrator privileges and gain access to restricted functionality.

## Table of contents

## Vulnerability overview

OopsSec Store provides a standard signup form that accepts an email and password. When a user submits the form, the frontend sends a JSON payload to the backend, which creates a new user record in the database. The backend does not validate or restrict the fields it accepts, allowing attackers to inject additional properties that the application blindly persists.

The attack flow is as follows:

1. An attacker intercepts the signup request using a proxy
2. The attacker adds a `role` field with value `ADMIN` to the JSON payload
3. The backend stores all received fields without validation
4. The newly created account has administrator privileges

## Locating the attack surface

Navigate to the signup page at `/signup`. The form presents two input fields: email and password.

![Signup form with email and password fields](../../assets/images/mass-assignment-admin-privilege-escalation/signup-form.webp)

When the form is submitted, the browser sends a POST request to `/api/auth/signup` with a JSON body containing the user-provided values. The backend processes this payload and creates a new user record.

## Exploitation

### Setting up request interception

Configure a proxy tool such as Burp Suite to intercept HTTP traffic:

1. Open Burp Suite and navigate to Proxy > Intercept
2. Enable interception
3. Configure the browser to route traffic through the proxy (typically `127.0.0.1:8080`)

All subsequent requests from the browser will be captured before reaching the server.

### Submitting the registration form

Fill in the signup form with arbitrary values:

- Email: `evil@oopssec.local`
- Password: `password123`

Click the Sign up button. Burp Suite captures the request before it reaches the server.

![Intercepted signup request in Burp Suite](../../assets/images/mass-assignment-admin-privilege-escalation/intercepted-request.webp)

### Injecting the role field

The original request body contains only the expected fields:

```json
{
  "email": "evil@oopssec.local",
  "password": "password123"
}
```

Modify the payload to include the `role` field:

```json
{
  "email": "evil@oopssec.local",
  "password": "password123",
  "role": "ADMIN"
}
```

Forward the modified request. The server processes the payload and creates the user account with the injected role value.

### Verifying administrator access

Upon successful registration, the application redirects to the admin dashboard at `/admin`. The presence of the admin interface confirms that the account was created with administrator privileges.

The flag is displayed on the admin dashboard:

![Admin dashboard displaying the flag](../../assets/images/mass-assignment-admin-privilege-escalation/admin-dashboard-flag.webp)

## Vulnerable code analysis

The vulnerability exists because the backend passes the entire request body to the database layer without filtering.

```typescript
const user = await prisma.user.create({
  data: {
    ...body, // All fields from request body are persisted
    password: hashedPassword,
  },
});
```

The spread operator (`...body`) copies every property from the request, including the `role` field. The database schema defines `role` as a valid column, so Prisma accepts and stores the value. There is no server-side logic to restrict which fields a client can provide.

## Remediation

### Explicit field extraction

Extract only the expected fields from the request body and explicitly set authorization-sensitive fields on the server:

```typescript
const { email, password } = req.body;

const user = await prisma.user.create({
  data: {
    email,
    password: hash(password),
    role: "CUSTOMER", // Server-controlled value
  },
});
```

This approach ignores any additional fields the client might send. The `role` field is always set to `CUSTOMER` regardless of request content.

### Input validation with schema enforcement

Use a validation library such as Zod to define and enforce the expected request structure:

```typescript
import { z } from "zod";

const signupSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
});

const validatedData = signupSchema.parse(req.body);
```

Schema validation rejects requests containing unexpected fields and ensures that only permitted data reaches the database layer.

Authorization-sensitive fields must always be controlled by the server. User input should never determine privilege levels, roles, or access permissions.
