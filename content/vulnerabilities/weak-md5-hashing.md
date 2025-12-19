# Weak MD5 Hashing Vulnerability

## Overview

This vulnerability demonstrates a critical security flaw where MD5 (Message Digest Algorithm 5) is used for password hashing. MD5 is cryptographically broken and vulnerable to collision attacks, rainbow table lookups, and brute force attacks. This makes it trivial for attackers to recover plaintext passwords from MD5 hashes, especially for weak passwords.

## Vulnerability Summary

The application uses MD5 to hash user passwords before storing them in the database. MD5 has been considered cryptographically broken since 2004. It is vulnerable to:

1. **Rainbow Table Attacks**: Pre-computed hash tables allow instant password recovery for common passwords
2. **Brute Force Attacks**: MD5 is fast to compute, making brute force attacks practical
3. **Collision Attacks**: Multiple inputs can produce the same hash, compromising security
4. **No Salt**: The implementation doesn't use salt, making rainbow table attacks even more effective

### Vulnerable Code

**MD5 Hashing:**

```typescript
const hashMD5 = (text: string): string => {
  return crypto.createHash("md5").update(text).digest("hex");
};

const hashedPassword = hashMD5(password);
```

**Account Enumeration:**

```typescript
const user = await prisma.user.findUnique({
  where: { email },
});

if (!user) {
  return NextResponse.json({ error: "Invalid credentials" }, { status: 401 });
}

if (user.password !== hashedPassword) {
  return NextResponse.json({ error: "Invalid password" }, { status: 401 });
}
```

The different error messages (`"Invalid credentials"` vs `"Invalid password"`) allow attackers to determine whether an email address is registered in the system.

## Impact

This vulnerability allows attackers to:

- **Recover plaintext passwords** from leaked database dumps
- **Perform credential stuffing attacks** using cracked passwords
- **Gain unauthorized access** to user accounts, including administrative accounts
- **Escalate privileges** by cracking admin passwords
- **Compromise multiple accounts** if users reuse passwords

## Exploitation

### How to Retrieve the Flag

To retrieve the flag `OSS{w34k_md5_h4sh1ng}`, you need to exploit the weak MD5 hashing vulnerability combined with account enumeration:

**Exploitation Steps:**

1. **Discover the data breach**: Navigate to the News page (accessible from the footer) where Fresh Products has announced a data breach
2. **Examine leaked data**: The News page displays a sample of leaked customer data.
3. **Crack the MD5 hashes**: Use one of the following methods to crack the MD5 hashes:

   **Option A: Online Tools**
   - Visit [CrackStation](https://crackstation.net/) or similar MD5 lookup services
   - Enter each MD5 hash to recover the plaintext passwords
   - One hash (`21232f297a57a5a743894a0e4a801fc3`) will reveal the password: `admin`

   **Option B: Command Line**

   ```bash
   # Using hashcat
   hashcat -m 0 21232f297a57a5a743894a0e4a801fc3 /usr/share/wordlists/rockyou.txt

   # Using john the ripper
   echo "21232f297a57a5a743894a0e4a801fc3" > hash.txt
   john --format=Raw-MD5 hash.txt
   ```

4. **Enumerate accounts using login form**: The login form leaks information about which accounts exist through different error messages:
   - If an account **does not exist**: The error message is `"Invalid credentials"`
   - If an account **exists but password is wrong**: The error message is `"Invalid password"`

   This allows you to enumerate which email addresses are valid accounts. Try common email patterns:
   - `admin@example.com`
   - `administrator@oss.com`
   - `admin@oss.com`
   - etc.

   When you try `admin@oss.com` with any password, you'll get `"Invalid password"` instead of `"Invalid credentials"`, confirming the account exists.

5. **Login as admin**: Use the cracked credentials (`admin@oss.com` / `admin`) to log in
6. **Access admin panel**: After login, you will be automatically redirected to `/admin`
7. **Retrieve the flag**: The admin panel will display the flag `OSS{w34k_md5_h4sh1ng}`

### Why This Works

- MD5 hashes for common passwords like "admin" are well-documented in rainbow tables
- The hash `21232f297a57a5a743894a0e4a801fc3` is the MD5 hash of "admin"
- Without salt, identical passwords always produce identical hashes
- Online databases contain millions of pre-computed MD5 hashes for common passwords
- The login endpoint returns different error messages based on whether an account exists, enabling account enumeration

### Code Fixes

**Before (Vulnerable):**

```typescript
const hashMD5 = (text: string): string => {
  return crypto.createHash("md5").update(text).digest("hex");
};

const hashedPassword = hashMD5(password);
```

**After (Secure):**

```typescript
import bcrypt from "bcryptjs";

const hashPassword = async (password: string): Promise<string> => {
  const saltRounds = 12;
  return await bcrypt.hash(password, saltRounds);
};

const verifyPassword = async (
  password: string,
  hash: string
): Promise<boolean> => {
  return await bcrypt.compare(password, hash);
};
```

## References

- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [CWE-916: Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html)
- [NIST Password Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [MD5 Collision Vulnerability](https://en.wikipedia.org/wiki/MD5#Security)
- [OWASP Top 10 - Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)

## Flag

The flag for this vulnerability is: **OSS{w34k_md5_h4sh1ng}**

The flag can be retrieved by:

1. Finding the leaked password hashes on the News page (emails are not included in the leak)
2. Cracking the MD5 hashes to recover plaintext passwords
3. Using account enumeration via the login form to identify which email addresses exist
4. Identifying the admin account email address
5. Logging in with the admin credentials
6. Accessing the admin panel where the flag will be displayed
