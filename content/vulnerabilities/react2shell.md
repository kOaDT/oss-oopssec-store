# React2Shell Vulnerability (CVE-2025-55182)

## Overview

CVE-2025-55182, also known as **React2Shell**, is a critical pre-authentication remote code execution vulnerability affecting React Server Components. This vulnerability allows unauthenticated attackers to execute arbitrary JavaScript code on the server by crafting malicious payloads that exploit prototype chain traversal and unsafe property access patterns.

**CVSS Score:** 10.0 (Critical)

## Affected Versions

- React Server Components 19.0.0, 19.1.0, 19.1.1, and 19.2.0
- Packages: `react-server-dom-parcel`, `react-server-dom-turbopack`, `react-server-dom-webpack`

## Vulnerability Summary

CVE-2025-55182 is an unsafe deserialization vulnerability in React Server Components' Flight protocol implementation. The vulnerability stems from how React Server Components deserialize Flight protocol payloads. When processing module references, the code uses bracket notation to access properties (`moduleExports[metadata[2]]`), which traverses the entire JavaScript prototype chain. This allows attackers to reference properties that weren't explicitly exported, including the `constructor` property, which provides access to the global `Function` constructor.

By chaining prototype pollution techniques with React's internal chunk processing mechanisms, an attacker can construct a payload that ultimately executes arbitrary code through the Function constructor.

## Root Cause

The vulnerability occurs when:

1. **Unsafe Deserialization**: React Server Components deserialize Flight protocol payloads without proper validation
2. **Prototype Chain Traversal**: Bracket notation property access (`moduleExports[metadata[2]]`) traverses the entire JavaScript prototype chain
3. **Constructor Access**: Attackers can access the `constructor` property, providing access to the global `Function` constructor
4. **Code Execution**: By chaining prototype pollution with React's chunk processing, arbitrary code can be executed

## Impact

This vulnerability allows attackers to:

- Execute arbitrary code on the server
- Read sensitive files (environment variables, configuration files, etc.)
- Establish reverse shells
- Exfiltrate data
- Perform any operation the Node.js process has permissions to execute

### Potential Consequences

- Remote code execution on the server
- Unauthorized access to sensitive data
- System compromise
- Data exfiltration
- Privilege escalation

## Exploitation

### How to Retrieve the Flag

To retrieve the flag `OSS{r3act2sh3ll}`, you need to exploit this vulnerability to execute code on the server. The flag is stored in the `.env.local` file on the server.

**Exploitation Steps:**

1. Craft a malicious payload that exploits the unsafe deserialization vulnerability
2. Send the payload to the vulnerable endpoint (typically a POST request to the root path)
3. The payload should execute `cat .env.local` on the server to read the environment file
4. The flag will be returned in the response

**Example Payload Structure:**

The payload consists of multipart form fields that exploit prototype pollution:

- **Field 0**: A fake chunk object containing prototype pollution references (`$1:__proto__:then`), a Blob reference (`$B1337`), and a polluted `_response` object with malicious `_prefix` containing the command to execute
- **Field 1**: A reference to field 0 (`$@0`)
- **Field 2**: An empty array (`[]`)

The malicious code in `_prefix` reads `.env.local` using Node.js's `child_process.execSync` and embeds the result in an error digest.

**Note:** For a complete working proof-of-concept, refer to the [GitHub POC repository](https://github.com/kOaDT/poc-cve-2025-55182).

## Detection

To identify this vulnerability in your application:

1. Check if you're using affected React Server Components versions (19.0.0, 19.1.0, 19.1.1, or 19.2.0)
2. Review Flight protocol payload processing
3. Audit deserialization mechanisms in React Server Components
4. Look for unsafe property access patterns using bracket notation
5. Check for missing input validation in server-side rendering contexts

## Remediation

### Immediate Actions

1. **Update React**: Upgrade to React Server Components version 19.2.1 or later
2. **Update Next.js**: If using Next.js, ensure you're using a version that includes the patched React Server Components
3. **Review Dependencies**: Check all packages that depend on React Server Components
4. **Monitor for Exploitation**: Review server logs for suspicious payloads

## References

- [CVE-2025-55182 Details](https://www.cyberhub.blog/cves/CVE-2025-55182)
- [GitHub POC Repository](https://github.com/kOaDT/poc-cve-2025-55182)
- [React Security Advisory](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components)
- [Facebook Security Advisory](https://www.facebook.com/security/advisories/cve-2025-55182)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2025-55182)
- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)

## Flag

The flag for this vulnerability is: **OSS{r3act2sh3ll}**

The flag can be found in the `.env.local` file on the server. To retrieve it, you must exploit the React2Shell vulnerability to execute `cat .env.local` on the server.
