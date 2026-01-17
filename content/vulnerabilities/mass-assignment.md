# Mass Assignment / Parameter Pollution Vulnerability

## Overview

This vulnerability occurs when an application accepts user input and directly assigns it to model attributes without proper filtering or whitelisting. This allows attackers to modify fields that should not be user-controllable, such as role, permissions, or other sensitive attributes.

## Root Cause

The vulnerability stems from:

1. **Unfiltered User Input**: The signup endpoint accepts all fields from the request body without validation
2. **Direct Assignment**: User-provided data is directly assigned to the database model without whitelisting
3. **Missing Input Validation**: No checks are performed to ensure only allowed fields are processed
4. **Trust in Client Data**: The application trusts that users will only send expected fields

## Impact

This vulnerability allows attackers to:

- **Escalate privileges** by setting themselves as administrators during account creation
- **Bypass access controls** by modifying sensitive fields
- **Gain unauthorized access** to administrative functions
- **Compromise system security** by creating accounts with elevated privileges

## Exploitation

### How to Retrieve the Flag

To retrieve the flag `OSS{m4ss_4ss1gnm3nt_vuln3r4b1l1ty}`, you need to exploit the mass assignment vulnerability during account creation:

**Exploitation Steps:**

1. **Navigate to Sign Up page**: Click on "Sign Up" in the header to access the registration form
2. **Intercept the request**: Use browser developer tools or a proxy tool (like Burp Suite) to intercept the signup request
3. **Modify the request payload**: Add the `role` field to the request body with the value `"ADMIN"`:

   ```json
   {
     "email": "attacker@example.com",
     "password": "password123",
     "role": "ADMIN"
   }
   ```

4. **Submit the modified request**: Send the request with the additional `role` field
5. **Account created with admin privileges**: The system will create an account with administrator role
6. **Access admin panel**: After signup, you will be automatically redirected to `/admin` if the role is ADMIN
7. **Retrieve the flag**: The admin panel will detect that you're an admin but not the expected one and display the flag

### Why This Works

- The signup endpoint accepts the `role` field directly from the request body
- No validation is performed to ensure only allowed fields are processed
- The application uses the provided `role` value without checking if it should be user-controllable
- By default, new accounts should be created with `role: "CUSTOMER"`, but the vulnerability allows overriding this

### Vulnerable Code

**Signup Route (Vulnerable):**

```typescript
export async function POST(request: Request) {
  const body = await request.json();
  const { email, password } = body;

  const userData: any = {
    email,
    password: hashedPassword,
    addressId: defaultAddress.id,
  };

  // VULNERABILITY: Accepts role from request body without validation
  if (body.role) {
    userData.role = body.role;
  }

  const user = await prisma.user.create({
    data: userData, // Direct assignment without whitelisting
  });
}
```

The code checks if `body.role` exists and directly assigns it to `userData`, allowing attackers to set themselves as administrators.

## Remediation

### Code Fixes

**Before (Vulnerable):**

```typescript
const userData: any = {
  email,
  password: hashedPassword,
  addressId: defaultAddress.id,
};

if (body.role) {
  userData.role = body.role; // VULNERABLE
}

const user = await prisma.user.create({
  data: userData,
});
```

**After (Secure):**

```typescript
// Define allowed fields explicitly
const allowedFields = ["email", "password", "addressId"];
const userData: {
  email: string;
  password: string;
  addressId: string;
  role?: string;
} = {
  email,
  password: hashedPassword,
  addressId: defaultAddress.id,
  role: "CUSTOMER", // Always set default role, never from user input
};

// Explicitly reject any role from user input
if (body.role) {
  return NextResponse.json(
    { error: "Role cannot be set during signup" },
    { status: 400 }
  );
}

const user = await prisma.user.create({
  data: userData,
});
```

**Alternative Secure Approach (Using Object Destructuring):**

```typescript
// Only extract allowed fields
const { email, password } = body;

const user = await prisma.user.create({
  data: {
    email,
    password: hashedPassword,
    addressId: defaultAddress.id,
    role: "CUSTOMER", // Always use default, never from input
  },
});
```

### Best Practices

1. **Never trust client input**: Always validate and sanitize user input
2. **Use whitelisting**: Only accept explicitly allowed fields
3. **Implement role-based access control**: Roles should only be assignable by administrators through separate endpoints
4. **Use type-safe DTOs**: Define strict TypeScript interfaces for request bodies
5. **Implement input validation middleware**: Use libraries like Zod or class-validator to validate input schemas
6. **Separate concerns**: User registration should never allow privilege escalation

## References

- [OWASP Mass Assignment](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
- [CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)
- [OWASP API Security Top 10 - API6:2019 - Mass Assignment](https://owasp.org/API-Security/editions/2019/en/0xa6-mass-assignment/)
