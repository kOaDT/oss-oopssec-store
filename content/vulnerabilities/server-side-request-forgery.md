# Server-Side Request Forgery (SSRF)

## Overview

This vulnerability demonstrates a critical security flaw where the application performs server-side HTTP requests using user-controlled URLs without proper validation, sanitization, or network restrictions. This allows attackers to make the server send requests to internal services, cloud metadata endpoints, or other sensitive resources that should not be accessible from the outside.

## Why This Is Dangerous

### Unrestricted Server-Side Requests

When an application fetches URLs provided by users without proper validation, it creates a severe security vulnerability:

1. **Internal network access** - Attackers can access internal services, APIs, and resources that are not exposed to the internet
2. **Cloud metadata exposure** - Access to cloud provider metadata endpoints (AWS, Azure, GCP) can reveal credentials and sensitive configuration
3. **Port scanning** - Attackers can scan internal network ports to discover services
4. **Bypass firewall rules** - The server can access resources behind firewalls that external users cannot reach
5. **Information disclosure** - Internal application pages, admin panels, and configuration files can be accessed
6. **Remote code execution** - In some cases, SSRF can lead to RCE through internal services

### What This Means

**Never trust user-provided URLs for server-side requests.** The server must:

- Validate and sanitize all URLs before fetching
- Use allowlists of permitted domains and protocols
- Block access to private IP ranges (127.0.0.1, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Block access to localhost and internal services
- Restrict protocols to HTTP/HTTPS only
- Implement proper timeout and size limits
- Use network-level restrictions when possible

## The Vulnerability

In this application, the support form submission endpoint (`/api/support`) is vulnerable to SSRF attacks because:

1. **No URL validation** - The endpoint accepts any URL without checking its format, protocol, or destination
2. **No IP filtering** - The server can fetch from localhost, private IPs, and internal services
3. **No protocol restrictions** - The endpoint doesn't restrict which protocols can be used
4. **No allowlist** - There's no whitelist of permitted domains
5. **Response disclosure** - The fetched content is returned verbatim to the user, exposing internal resources

### Vulnerable Code

**Support Form API Route (Vulnerable):**

```typescript
export async function POST(request: NextRequest) {
  const { email, title, description, screenshotUrl } = await request.json();

  let screenshotContent = null;
  if (screenshotUrl) {
    // ❌ No URL validation
    // ❌ No IP filtering
    // ❌ No protocol restrictions
    // ❌ No allowlist
    const response = await fetch(screenshotUrl);
    screenshotContent = await response.text();
  }

  return NextResponse.json({
    success: true,
    data: {
      email,
      title,
      description,
      screenshotContent, // ❌ Returns fetched content verbatim
    },
  });
}
```

The code directly fetches the user-provided URL without any validation, allowing attackers to make the server request internal resources.

## Exploitation

### How to Retrieve the Flag

To retrieve the flag `OSS{s3rv3r_s1d3_r3qu3st_f0rg3ry}`, you need to exploit the SSRF vulnerability:

**Prerequisites:**

1. The application must be running (the server needs to be able to make internal requests)
2. There must be an internal page that contains the flag (not accessible through normal navigation)

**Exploitation Steps:**

1. **Navigate to the Contact Support page:**
   - Click on "Contact Support" in the main navigation menu
   - Or navigate directly to `/support`

2. **Fill out the support form:**
   - Enter any email address (e.g., `attacker@example.com`)
   - Enter a title (e.g., `Support Request`)
   - Enter a description (e.g., `I need help with my order`)
   - **In the screenshot URL field, enter the URL of the internal secret page:**
     ```
     http://localhost:3000/internal
     ```

3. **Submit the form:**
   - Click the submit button
   - The frontend will call the `/api/support` endpoint
   - The server will fetch the URL you provided server-side
   - The server can access internal pages that external users cannot

4. **Retrieve the flag:**
   - The API response will include the HTML content of the internal page
   - Look for the flag `OSS{s3rv3r_s1d3_r3qu3st_f0rg3ry}` in the displayed content

## References

- [OWASP Server-Side Request Forgery (SSRF)](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
- [CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
- [OWASP API Security Top 10 - API8:2019 - Injection](https://owasp.org/API-Security/editions/2019/fr/0xa8-injection/)
- [PortSwigger - Server-Side Request Forgery (SSRF)](https://portswigger.net/web-security/ssrf)

## Flag

The flag for this vulnerability is: **OSS{s3rv3r_s1d3_r3qu3st_f0rg3ry}**

The flag can be retrieved by exploiting the SSRF vulnerability in the `/api/support` endpoint. Submit the support form with the URL of the internal secret page (e.g., `http://localhost:3000/internal`) in the screenshot URL field. The server will fetch this internal page and return its content, revealing the flag.
