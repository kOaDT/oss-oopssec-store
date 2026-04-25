# Server-Side Request Forgery (SSRF)

## Overview

SSRF happens when a server takes a URL from user input and dispatches an HTTP request to it without validating the destination. Because the request originates from the server, it reaches anywhere the server's network can reach: localhost services, internal admin panels, cloud metadata endpoints, the database, sibling services on the same VPC. Attackers who cannot reach those targets directly use the application as a proxy.

In this challenge, the support form endpoint (`POST /api/support`) accepts a `screenshotUrl`, fetches it server-side, and returns the response body to the caller. The fetch has no destination filtering and no protocol restriction.

## Why This Is Dangerous

- **Internal-only resources become reachable** — admin dashboards, debug pages, and unauthenticated internal APIs all open up.
- **Cloud metadata exposure** — `http://169.254.169.254/` on AWS/Azure/GCP yields IAM credentials when reachable.
- **Network reconnaissance** — response timing differentiates open ports from closed ones, even without content.
- **Exfiltration relay** — outbound requests with attacker-controlled query strings can carry data out of the network.
- **Pivoting** — a proxied request to an internal service can chain into command injection or RCE on that service.

## Vulnerable Code

```typescript
if (screenshotUrl) {
  const response = await fetch(screenshotUrl, {
    headers: { "X-Internal-Request": "true" },
  });
  screenshotContent = await response.text();
}

return NextResponse.json({
  success: true,
  data: { email, title, description, screenshotContent },
});
```

The URL is taken from the request body and passed straight to `fetch`. There is no check that the URL is HTTP(S), no check that it points to an external host, no DNS-resolution check against private ranges, and no allowlist of acceptable origins. The `X-Internal-Request: true` header makes the situation worse — internal services that grant trust based on a header are now reachable through this endpoint.

## Secure Implementation

Constrain the destination, the protocol, and the trust signals attached to the outbound request.

**Allowlist by origin.** If the feature only needs to fetch from a specific upload provider, only that origin should ever be reached:

```typescript
const ALLOWED_HOSTS = new Set(["uploads.example.com", "cdn.example.com"]);

const url = new URL(screenshotUrl);
if (url.protocol !== "https:" || !ALLOWED_HOSTS.has(url.hostname)) {
  return NextResponse.json(
    { error: "Invalid screenshot URL" },
    { status: 400 }
  );
}
```

**Resolve and check the IP.** When an allowlist is impossible, resolve the hostname and reject anything that lands on a loopback, link-local, or private range — repeat the check after each redirect to defeat DNS rebinding:

```typescript
import { lookup } from "dns/promises";
import ipaddr from "ipaddr.js";

const { address } = await lookup(url.hostname);
const parsed = ipaddr.parse(address);
const range = parsed.range();

if (
  [
    "private",
    "loopback",
    "linkLocal",
    "uniqueLocal",
    "carrierGradeNat",
  ].includes(range)
) {
  return NextResponse.json({ error: "Forbidden destination" }, { status: 400 });
}
```

**Minimize trust on the outbound request.** Strip ambient credentials, do not forward cookies, refuse to follow cross-origin redirects, set a hard timeout, and cap the response size. Do not attach internal headers like `X-Internal-Request`.

**Network-level controls.** Where possible, run the egress through an HTTP forward proxy that enforces the destination policy; this gives you a single point to log, alert, and update without redeploying every service.

## References

- [OWASP — Server-Side Request Forgery](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
- [PortSwigger — SSRF](https://portswigger.net/web-security/ssrf)
