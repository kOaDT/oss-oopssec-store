# Weak Password Hashing (MD5)

## Overview

MD5 is a fast, unsalted, collision-prone digest. It was designed for integrity checking, not password storage. Used as a password hash, it gives an attacker who has obtained the stored value almost no work to do: rainbow tables and GPU-based brute force recover common passwords in seconds, and the lack of a per-user salt means identical passwords produce identical hashes across users.

In this challenge, the application hashes passwords with `crypto.createHash("md5")` before storing them, then compares the user-supplied input against the stored hash on login. There is no salt, no work factor, and the login endpoint emits two distinct error messages for "user not found" vs "wrong password", making account enumeration trivial in addition to the hashing weakness itself.

## Why This Is Dangerous

- **Hashes are effectively reversible** — common passwords resolve from rainbow tables instantly.
- **GPU brute force is cheap** — billions of MD5 candidates per second per GPU.
- **No salt** — pre-computed tables work uniformly across the user base.
- **Cross-account reuse** — identical hashes reveal users sharing the same password.
- **Account enumeration** — separate "Invalid credentials" / "Invalid password" messages let attackers harvest valid emails before brute force.

## Vulnerable Code

```typescript
const hashMD5 = (text: string): string => {
  return crypto.createHash("md5").update(text).digest("hex");
};

const hashedPassword = hashMD5(password);

if (!user) {
  return NextResponse.json({ error: "Invalid credentials" }, { status: 401 });
}
if (user.password !== hashedPassword) {
  return NextResponse.json({ error: "Invalid password" }, { status: 401 });
}
```

`hashMD5` returns the same 128-bit value for the same input every time, with no randomization. The lookup-then-compare pattern leaks the existence of an account through error-message differences and timing.

## Secure Implementation

Use a password-specific KDF that is slow by design, salts every record automatically, and supports tunable work factors.

```typescript
import bcrypt from "bcryptjs";

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, 12);
}

export async function verifyPassword(
  password: string,
  hash: string
): Promise<boolean> {
  return bcrypt.compare(password, hash);
}
```

`argon2id` is preferable on greenfield projects (it is the OWASP-recommended default); `scrypt` and `bcrypt` remain acceptable. Whatever the choice, the work factor must be tuned so a single hash takes hundreds of milliseconds on production hardware, and re-tuned over time as hardware improves.

Two extra controls that belong in the same change:

- **Constant-shape responses.** Return the same error and the same timing whether the email exists or not. Run the password verifier even when the user is missing (using a dummy hash) to flatten timing.
- **Rotate-on-login.** When a user logs in successfully and their record still uses the old algorithm or work factor, transparently re-hash with the new parameters and update the row.

## References

- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [CWE-916: Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html)
- [CWE-759: Use of a One-Way Hash without a Salt](https://cwe.mitre.org/data/definitions/759.html)
- [NIST SP 800-63B — Memorized Secret Verifiers](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [OWASP Top 10 — A04:2025 Cryptographic Failures](https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/)
