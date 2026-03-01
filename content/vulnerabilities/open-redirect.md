# Open Redirect

## Overview

This vulnerability demonstrates an open redirect flaw in the application's login flow. The login page accepts a user-controlled `redirect` query parameter and navigates to the specified URL after successful authentication, without validating whether the destination is safe or belongs to the same origin. This allows attackers to craft malicious login links that redirect victims to phishing sites or internal resources after they authenticate.

## Why This Is Dangerous

### Unvalidated Redirect URLs

When an application redirects users based on unvalidated input, it creates multiple attack vectors:

1. **Phishing attacks** - Attackers craft login URLs that redirect victims to fake login pages or credential harvesters after authentication
2. **Credential theft** - Combined with look-alike domains, users believe they are still on the legitimate site
3. **Token leakage** - Authentication tokens or session cookies may be sent to attacker-controlled servers via the Referer header
4. **Trust exploitation** - The redirect originates from a legitimate domain, bypassing user suspicion and email filters
5. **Internal resource access** - Redirects can target internal endpoints not intended for direct user access

### What This Means

**Always validate redirect URLs before performing navigation.** The application must:

- Validate that redirect targets are relative paths or belong to an allowlist of trusted domains
- Reject absolute URLs pointing to external origins
- Strip or encode dangerous URL schemes
- Use a server-side allowlist approach rather than client-side blocklist filtering

## The Vulnerability

In this application, the login page is vulnerable to open redirect because:

1. **No URL validation** - The `redirect` query parameter is used as-is without any checks
2. **Client-side redirect** - After authentication, the browser navigates directly to the unvalidated URL
3. **Accepts any scheme** - The redirect target can be an absolute URL with any protocol, including external domains
4. **No origin check** - There is no verification that the redirect stays within the application's origin

### Vulnerable Code

**Login Form (Vulnerable):**

```typescript
const redirect = searchParams.get("redirect");

// After successful login:
if (redirect) {
  window.location.href = redirect; // No validation
}
```

The code reads the `redirect` parameter from the URL and navigates to it directly without checking whether the destination is a safe, same-origin path.

## Exploitation

### How to Retrieve the Flag

To retrieve the flag `OSS{0p3n_r3d1r3ct_l0g1n_byp4ss}`, you need to exploit the open redirect vulnerability to reach an internal OAuth callback endpoint:

**Prerequisites:**

1. Valid login credentials (test account: `alice@example.com` / `iloveduck`)
2. Knowledge of the internal callback endpoint path

**Exploitation Steps:**

1. **Discover the redirect parameter:**
   - Try accessing a protected page like `/profile` while logged out
   - Notice the redirect to `/login?redirect=%2Fprofile`
   - The `redirect` parameter controls post-login navigation

2. **Identify the internal endpoint:**
   - Use directory enumeration to discover `/internal/oauth/callback`
   - This endpoint is an OAuth integration debug page not linked in the UI

3. **Craft the malicious login URL:**

   ```
   /login?redirect=/internal/oauth/callback
   ```

4. **Log in through the crafted URL:**
   - Navigate to the URL above
   - Enter valid credentials and submit
   - After login, the application redirects to the internal callback page

5. **Retrieve the flag:**
   - The OAuth callback page displays the flag: `OSS{0p3n_r3d1r3ct_l0g1n_byp4ss}`

## References

- [OWASP Unvalidated Redirects and Forwards](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect)
- [CWE-601: URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html)
- [PortSwigger - Open Redirect](https://portswigger.net/kb/issues/00500100_open-redirection-reflected)
